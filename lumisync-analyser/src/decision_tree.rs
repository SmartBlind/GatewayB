use std::io::{self, Read, Write};

use rand::Rng;

use crate::criterion::Criterion;
use crate::node::{Node, NodeBuilder};
use crate::table::Table;

#[derive(Debug, Clone)]
pub struct DecisionTreeOptions {
    pub max_features: Option<usize>,
    pub max_depth: usize,
    pub min_samples_split: usize,
}

impl Default for DecisionTreeOptions {
    fn default() -> Self {
        Self {
            max_features: None,
            max_depth: 64,
            min_samples_split: 2,
        }
    }
}

#[derive(Debug)]
pub struct DecisionTree {
    root: Node,
}

impl DecisionTree {
    pub fn fit<R: Rng + ?Sized, T: Criterion>(
        rng: &mut R,
        criterion: T,
        mut table: Table,
        options: DecisionTreeOptions,
    ) -> Self {
        let max_features = options.max_features.unwrap_or_else(|| table.features_len());
        let mut builder = NodeBuilder {
            rng,
            max_features,
            max_depth: options.max_depth,
            min_samples_split: options.min_samples_split,
            criterion,
        };
        let root = builder.build(&mut table, 1);

        Self { root }
    }

    pub fn predict(&self, xs: &[f64]) -> f64 {
        self.root.predict(xs)
    }

    pub fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        self.root.serialize(writer)
    }

    pub fn deserialize<R: Read>(reader: &mut R) -> io::Result<Self> {
        Ok(Self { root: Node::deserialize(reader)? })
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::path::Path;

    use rand;

    use crate::criterion::Mse;
    use crate::table::TableBuilder;

    use super::*;

    #[test]
    fn test_decision_tree_regression() -> Result<(), Box<dyn Error>> {
        let mut table_builder = TableBuilder::new();
        let path = Path::new("datasets/tests/boston_house_prices.csv");
        table_builder.add_csv(path).unwrap();

        let table = table_builder.build()?;

        let regressor = DecisionTree::fit(&mut rand::thread_rng(), Mse, table, Default::default());
        assert_eq!(
            regressor.predict(&[
                0.00632, 18.0, 2.31, 0.0, 0.538, 6.575, 65.2, 4.09, 1.0, 296.0, 15.3, 396.9, 4.98
            ][..]),
            24.0
        );

        Ok(())
    }
}