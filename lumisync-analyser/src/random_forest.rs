use std::io::{self, ErrorKind, Read, Write};
use std::num::NonZeroUsize;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use rand::{random, Rng, SeedableRng};
use rand::rngs::StdRng;
use rayon::iter::{IntoParallelIterator, ParallelIterator};

use crate::{mean, most_frequent};
use crate::criterion::Criterion;
use crate::decision_tree::{DecisionTree, DecisionTreeOptions};
use crate::table::Table;

#[derive(Debug, Clone, Default)]
#[repr(u16)]
pub enum RandomForestType {
    #[default]
    Regressor = 0,
    Classifier = 1,
}

impl TryFrom<u16> for RandomForestType {
    type Error = io::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(RandomForestType::Regressor),
            1 => Ok(RandomForestType::Classifier),
            _ => Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("Value {} is out of range for RandomForestType", value),
            )),
        }
    }
}

#[derive(Debug)]
pub struct RandomForest {
    pub forest_type: RandomForestType,
    pub forest: Vec<DecisionTree>,
}

impl RandomForest {
    pub fn predict<'a>(&'a self, xs: &'a [f64]) -> f64 {
        let predict = self.predict_individuals(xs);

        match self.forest_type {
            RandomForestType::Regressor => mean(predict),
            RandomForestType::Classifier => most_frequent(predict),
        }
    }

    pub fn predict_individuals<'a>(
        &'a self,
        xs: &'a [f64],
    ) -> impl 'a + Iterator<Item=f64> {
        self.forest.iter().map(move |tree| tree.predict(xs))
    }

    pub fn serialize<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u16::<BigEndian>(self.forest_type.to_owned() as u16)?;
        writer.write_u16::<BigEndian>(self.forest.len() as u16)?;
        for tree in &self.forest {
            tree.serialize(&mut writer)?;
        }

        Ok(())
    }

    pub fn deserialize<R: Read>(mut reader: R) -> io::Result<Self> {
        let forest_type = reader.read_u16::<BigEndian>()?;
        let forest_len = reader.read_u16::<BigEndian>()?;
        let forest = (0..forest_len)
            .map(|_| DecisionTree::deserialize(&mut reader))
            .collect::<io::Result<Vec<_>>>()?;

        Ok(Self {
            forest_type: RandomForestType::try_from(forest_type)?,
            forest,
        })
    }
}

#[derive(Debug, Clone)]
pub struct RandomForestBuilder {
    pub forest_type: RandomForestType,
    pub trees: NonZeroUsize,
    pub max_features: Option<NonZeroUsize>,
    pub max_samples: Option<NonZeroUsize>,
    pub seed: Option<u64>,
    pub parallel: bool,
}

impl RandomForestBuilder {
    pub fn fit<T: Criterion>(
        &self,
        criterion: T,
        table: Table,
    ) -> RandomForest {
        let forest = if self.parallel {
            self.tree_rngs()
                .collect::<Vec<_>>()
                .into_par_iter()
                .map(|mut rng| self.tree_fit(&mut rng, criterion.clone(), &table))
                .collect::<Vec<_>>()
        } else {
            self.tree_rngs()
                .map(|mut rng| self.tree_fit(&mut rng, criterion.clone(), &table))
                .collect::<Vec<_>>()
        };

        RandomForest {
            forest_type: self.forest_type.clone(),
            forest,
        }
    }

    fn tree_fit<R: Rng + ?Sized, T: Criterion>(
        &self,
        rng: &mut R,
        criterion: T,
        table: &Table,
    ) -> DecisionTree {
        let max_features = self.decide_max_features(table);
        let max_samples = self.max_samples.map_or(table.rows_len(), |n| n.get());
        let table = table.bootstrap_sample(rng, max_samples);
        DecisionTree::fit(rng, criterion, table, DecisionTreeOptions {
            max_features: Some(max_features),
            ..Default::default()
        })
    }

    fn tree_rngs(&self) -> impl Iterator<Item=StdRng> {
        let seed_u64 = self.seed.unwrap_or_else(|| random());
        let mut seed = [0u8; 32];
        (&mut seed[0..8]).copy_from_slice(&seed_u64.to_be_bytes()[..]);
        let mut rng = StdRng::from_seed(seed);
        (0..self.trees.get()).map(move |_| {
            let mut seed = [0u8; 32];
            rng.fill(&mut seed);
            StdRng::from_seed(seed)
        })
    }

    fn decide_max_features(&self, table: &Table) -> usize {
        if let Some(n) = self.max_features {
            n.get()
        } else {
            (table.features_len() as f64).sqrt().ceil() as usize
        }
    }
}

impl Default for RandomForestBuilder {
    fn default() -> Self {
        Self {
            forest_type: Default::default(),
            trees: NonZeroUsize::new(100).unwrap(),
            max_features: None,
            max_samples: None,
            seed: None,
            parallel: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::path::Path;

    use crate::criterion::{Gini, Mse};
    use crate::table::TableBuilder;

    use super::*;

    #[test]
    fn test_random_forest_regressor() -> Result<(), Box<dyn Error>> {
        let mut table_builder = TableBuilder::new();
        let path = Path::new("datasets/tests/boston_house_prices.csv");
        table_builder.add_csv(path).unwrap();

        let table = table_builder.build()?;

        let regressor = RandomForestBuilder {
            seed: Some(0),
            parallel: true,
            ..Default::default()
        }
            .fit(Mse, table);
        assert_eq!(
            regressor.predict(&[
                0.00632, 18.0, 2.31, 0.0, 0.538, 6.575, 65.2, 4.09, 1.0, 296.0, 15.3, 396.9, 4.98
            ][..]),
            25.393999999999995
        );

        let mut bytes = Vec::new();
        regressor.serialize(&mut bytes)?;
        let regressor_deserialized = RandomForest::deserialize(&mut &bytes[..])?;
        assert_eq!(
            regressor_deserialized.predict(&[
                0.00632, 18.0, 2.31, 0.0, 0.538, 6.575, 65.2, 4.09, 1.0, 296.0, 15.3, 396.9, 4.98
            ][..]),
            25.393999999999995
        );

        Ok(())
    }

    #[test]
    fn test_random_forest_classifier() -> Result<(), Box<dyn Error>> {
        let mut table_builder = TableBuilder::new();
        let path = Path::new("datasets/tests/iris.csv");
        table_builder.add_csv(path).unwrap();

        let table = table_builder.build()?;

        let classifier = RandomForestBuilder {
            seed: Some(0),
            parallel: true,
            ..Default::default()
        }
            .fit(Gini, table.clone());
        assert_eq!(classifier.predict(&[5.1, 3.5, 1.4, 0.0]), 0.0);

        let mut bytes = Vec::new();
        classifier.serialize(&mut bytes)?;
        let classifier_deserialized = RandomForest::deserialize(&mut &bytes[..])?;
        assert_eq!(classifier_deserialized.predict(&[5.1, 3.5, 1.4, 0.0]), 0.0);

        Ok(())
    }
}
