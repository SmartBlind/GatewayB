use crate::{histogram, mean};

#[derive(Debug, Default, Clone)]
pub enum CriterionType {
    #[default]
    Regression,
    Classification,
}

pub trait Criterion: Send + Sync + Clone {
    const CRITERION_TYPE: CriterionType;

    fn criterion_type(&self) -> CriterionType {
        Self::CRITERION_TYPE
    }

    fn calculate<T>(&self, xs: T) -> f64
        where
            T: Iterator<Item = f64> + Clone;
}

#[derive(Debug, Clone)]
pub struct Mse;

impl Criterion for Mse {
    const CRITERION_TYPE: CriterionType = CriterionType::Regression;

    fn calculate<T>(&self, ys: T) -> f64
        where
            T: Iterator<Item = f64> + Clone,
    {
        let n = ys.clone().count() as f64;
        let m = mean(ys.clone());
        ys.map(|x| (x - m).powi(2)).sum::<f64>() / n
    }
}

#[derive(Debug, Clone)]
pub struct Gini;

impl Criterion for Gini {
    const CRITERION_TYPE: CriterionType = CriterionType::Classification;

    fn calculate<T>(&self, ys: T) -> f64
        where
            T: Iterator<Item = f64> + Clone,
    {
        let (histogram, n) = histogram(ys);
        1.0 - histogram
            .into_iter()
            .map(|(_, count)| (count as f64 / n as f64).powi(2))
            .sum::<f64>()
    }
}

#[derive(Debug, Clone)]
pub struct Entropy;

impl Criterion for Entropy {
    const CRITERION_TYPE: CriterionType = CriterionType::Classification;

    fn calculate<T>(&self, ys: T) -> f64
        where
            T: Iterator<Item = f64> + Clone,
    {
        let (histogram, n) = histogram(ys);
        histogram
            .into_iter()
            .map(|(_, count)| {
                let p = count as f64 / n as f64;
                -p * p.log2()
            })
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mse() {
        assert_eq!(Mse.calculate([50.0, 60.0, 70.0, 70.0, 100.0].iter().copied()), 280.0);
    }

    #[test]
    fn test_gini() {
        assert_eq!(Gini.calculate([0.0, 1.0, 0.0, 1.0, 1.0, 0.0].iter().copied()), 0.5);
        assert_eq!(Gini.calculate([0.0, 0.0, 0.0, 0.0, 0.0, 0.0].iter().copied()), 0.0);
        assert_eq!(Gini.calculate([0.0, 1.0, 0.0, 0.0, 0.0, 0.0].iter().copied()), 0.2777777777777777);
    }

    #[test]
    fn test_entropy() {
        assert_eq!(Entropy.calculate([0.0, 1.0, 0.0, 1.0].iter().copied()), 1.0);
        assert_eq!(Entropy.calculate([0.0, 0.0, 0.0, 0.0].iter().copied()), 0.0);
        assert_eq!(Entropy.calculate([0.0, 1.0, 0.0, 0.0].iter().copied()), 0.8112781244591328);
    }
}
