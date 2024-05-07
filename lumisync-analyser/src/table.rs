use std::iter::once;
use std::ops::Range;
use std::path::Path;

use csv::Reader;
use ordered_float::OrderedFloat;
use rand::prelude::SliceRandom;
use rand::Rng;

#[derive(Debug, Clone)]
pub struct Table<'a> {
    pub row_index: Vec<usize>,
    pub row_range: Range<usize>,
    pub columns: &'a [Vec<f64>],
}

impl<'a> Table<'a> {
    pub fn rows<'b>(&'b self) -> impl 'b + Iterator<Item = Vec<f64>> + Clone {
        self.row_indices().map(move |i| {
            (0..self.columns.len()).map(|j| self.columns[j][i]).collect()
        })
    }

    pub fn filter<F>(&mut self, f: F) -> usize
        where
            F: Fn(&[f64]) -> bool,
    {
        let mut n = 0;
        let mut i = self.row_range.start;
        while i < self.row_range.end {
            let row_i = self.row_index[i];
            let row = (0..self.columns.len())
                .map(|j| self.columns[j][row_i])
                .collect::<Vec<_>>();
            if f(&row) {
                i += 1;
            } else {
                self.row_index.swap(i, self.row_range.end - 1);
                self.row_range.end -= 1;
                n += 1;
            }
        }
        n
    }

    pub fn train_test_split<R: Rng + ?Sized>(
        mut self,
        rng: &mut R,
        test_rate: f64,
    ) -> (Self, Self) {
        (&mut self.row_index[self.row_range.start..self.row_range.end]).shuffle(rng);
        let test_num = (self.rows_len() as f64 * test_rate).round() as usize;

        let mut train = self.clone();
        let mut test = self;
        test.row_range.end = test.row_range.start + test_num;
        train.row_range.start = test.row_range.end;

        (train, test)
    }

    pub fn target<'b>(&'b self) -> impl 'b + Iterator<Item = f64> + Clone {
        self.column(self.columns.len() - 1)
    }

    pub fn column<'b>(&'b self, column_index: usize, ) -> impl 'b + Iterator<Item = f64> + Clone {
        self.row_indices().map(move |i| self.columns[column_index][i])
    }

    pub fn features_len(&self) -> usize {
        self.columns.len() - 1
    }

    pub fn rows_len(&self) -> usize {
        self.row_range.end - self.row_range.start
    }

    fn row_indices<'b>(&'b self) -> impl 'b + Iterator<Item = usize> + Clone {
        self.row_index[self.row_range.start..self.row_range.end].iter().copied()
    }

    pub fn sort_rows_by_column(&mut self, column: usize) {
        let columns = &self.columns;
        (&mut self.row_index[self.row_range.start..self.row_range.end])
            .sort_by_key(|&x| OrderedFloat(columns[column][x]))
    }

    pub fn bootstrap_sample<R: Rng + ?Sized>(
        &self,
        rng: &mut R,
        max_samples: usize,
    ) -> Self {
        let samples = std::cmp::min(max_samples, self.rows_len());
        let row_index = (0..samples)
            .map(|_| self.row_index[rng.gen_range(self.row_range.start..self.row_range.end)])
            .collect::<Vec<_>>();
        let row_range = Range { start: 0, end: samples };

        Self {
            row_index,
            row_range,
            columns: self.columns,
        }
    }

    pub fn split_points<'b>(
        &'b self,
        column_index: usize,
    ) -> impl 'b + Iterator<Item = (Range<usize>, f64)> {
        // Assumption: `self.columns[column]` has been sorted.
        let column = &self.columns[column_index];
        self.row_indices()
            .map(move |i| column[i])
            .enumerate()
            .scan(None, move |prev, (i, x)| {
                if prev.is_none() {
                    *prev = Some((x, i));
                    Some(None)
                } else if prev.map_or(false, |(y, _)| (y - x).abs() > f64::EPSILON) {
                    let (y, _) = prev.unwrap();
                    *prev = Some((x, i));

                    let r = Range { start: 0, end: i };
                    Some(Some((r, (x + y) / 2.0)))
                } else {
                    Some(None)
                }
            })
            .filter_map(|t| t)
    }

    pub fn with_split<F, T>(&mut self, row: usize, mut f: F) -> (T, T)
        where
            F: FnMut(&mut Self) -> T,
    {
        let row = row + self.row_range.start;
        let original = self.row_range.clone();

        self.row_range.end = row;
        let left = f(self);
        self.row_range.end = original.end;

        self.row_range.start = row;
        let right = f(self);
        self.row_range.start = original.start;

        (left, right)
    }
}

#[derive(Debug)]
pub struct TableBuilder {
    pub columns: Vec<Vec<f64>>,
}

impl TableBuilder {
    pub fn new() -> Self {
        Self {
            columns: Vec::new(),
        }
    }

    pub fn add_row(&mut self, features: &[f64], target: f64) -> Result<(), TableError> {
        if self.columns.is_empty() {
            self.columns = vec![Vec::new(); features.len() + 1];
        }

        if self.columns.len() != features.len() + 1 {
            Err(TableError::ColumnSizeMismatch)?
        }

        if !target.is_finite() {
            Err(TableError::NonFiniteTarget)?
        }

        let column_data = self.columns
            .iter_mut()
            .zip(features.iter().copied().chain(once(target)));

        for (column, value) in column_data {
            column.push(value);
        }

        Ok(())
    }

    pub fn add_csv<P: AsRef<Path>>(&mut self, path: P) -> Result<(), TableError> {
        let mut rdr = Reader::from_path(path).map_err(|e| TableError::CSVError(e.to_string()))?;
        let mut columns: Vec<Vec<f64>> = Vec::new();
        let mut first_row = true;

        for result in rdr.deserialize::<Vec<f64>>() {
            let row: Vec<f64> = result.map_err(|e| TableError::CSVError(e.to_string()))?;

            if first_row {
                columns.resize(row.len(), Vec::new());
                first_row = false;
            }

            for (i, &value) in row.iter().enumerate() {
                if i < columns.len() {
                    columns[i].push(value);
                } else {
                    Err(TableError::ColumnSizeMismatch)?
                }
            }
        }

        for col in columns {
            self.columns.push(col);
        }

        Ok(())
    }

    pub fn build(&self) -> Result<Table, TableError> {
        if self.columns.is_empty() || self.columns[0].is_empty() {
            Err(TableError::EmptyTable)?
        }

        let rows_len = self.columns[0].len();

        Ok(Table {
            row_index: (0..rows_len).collect(),
            row_range: Range { start: 0, end: rows_len, },
            columns: &self.columns,
        })
    }
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum TableError {
    #[error("Table must have at least one column and one row")]
    EmptyTable,

    #[error("Some of rows have a different column count from others")]
    ColumnSizeMismatch,

    #[error("Target column contains non finite numbers")]
    NonFiniteTarget,

    #[error("Internal csv related error: {0}")]
    CSVError(String),
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    #[test]
    fn test_add_csv() -> Result<(), Box<dyn Error>> {
        let mut table_builder = TableBuilder::new();
        let path = Path::new("datasets/tests/iris.csv");
        table_builder.add_csv(path).unwrap();
        let table = table_builder.build()?;
        assert_eq!(table.rows_len(), 150);

        Ok(())
    }

    #[test]
    fn test_train_test_split() -> Result<(), Box<dyn Error>> {
        let mut table_builder = TableBuilder::new();
        for _ in 0..100 {
            table_builder.add_row(&[0.0], 1.0)?;
        }
        let table = table_builder.build()?;
        assert_eq!(table.rows_len(), 100);

        let (train, test) = table.train_test_split(&mut rand::thread_rng(), 0.25);
        assert_eq!(train.rows_len(), 75);
        assert_eq!(test.rows_len(), 25);

        Ok(())
    }

    #[test]
    fn test_filter() -> Result<(), Box<dyn Error>> {
        let mut table_builder = TableBuilder::new();
        for i in 0..100 {
            table_builder.add_row(&[0.0], i as f64)?;
        }
        let mut table = table_builder.build()?;
        assert_eq!(table.rows_len(), 100);

        let removed = table.filter(|row| row[row.len() - 1] < 10.0);
        assert_eq!(removed, 90);
        assert_eq!(table.rows_len(), 10);

        Ok(())
    }
}
