use std::io::{self, Error, ErrorKind, Read, Write};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use rand::Rng;
use rand::seq::SliceRandom;

use crate::{mean, most_frequent};
use crate::criterion::{Criterion, CriterionType};
use crate::table::Table;

#[derive(Debug)]
pub struct SplitPoint {
    pub column: usize,
    pub value: f64,
}

impl SplitPoint {
    pub fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_u16::<BigEndian>(self.column as u16)?;
        writer.write_f64::<BigEndian>(self.value)?;

        Ok(())
    }

    pub fn deserialize<R: Read>(reader: &mut R) -> io::Result<Self> {
        let column = reader.read_u16::<BigEndian>()? as usize;
        let value = reader.read_f64::<BigEndian>()?;

        Ok(Self { column, value })
    }
}

#[derive(Debug)]
pub enum Node {
    Leaf(f64),
    Children {
        split: SplitPoint,
        left: Box<Node>,
        right: Box<Node>,
    },
}

impl Node {
    pub fn predict(&self, xs: &[f64]) -> f64 {
        match self {
            Node::Leaf(value) => *value,
            Node::Children { split, left, right } => {
                if xs[split.column] < split.value {
                    left.predict(xs)
                } else {
                    right.predict(xs)
                }
            },
        }
    }

    pub fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        match &self {
            Node::Leaf(value) => {
                writer.write_u8(0)?;
                writer.write_f64::<BigEndian>(*value)?;
            },
            Node::Children { left, right, split } => {
                writer.write_u8(1)?;
                split.serialize(writer)?;
                left.serialize(writer)?;
                right.serialize(writer)?;
            },
        }

        Ok(())
    }

    pub fn deserialize<R: Read>(reader: &mut R) -> io::Result<Self> {
        match reader.read_u8()? {
            0 => Ok(Node::Leaf(reader.read_f64::<BigEndian>()?)),
            1 => {
                let split = SplitPoint::deserialize(reader)?;
                let left = Box::new(Node::deserialize(reader)?);
                let right = Box::new(Node::deserialize(reader)?);

                Ok(Node::Children { split, left, right })
            },
            v => Err(Error::new(ErrorKind::InvalidData, format!("unknown node type {}", v))),
        }
    }
}

#[derive(Debug)]
pub struct NodeBuilder<R, T> {
    pub rng: R,
    pub max_features: usize,
    pub max_depth: usize,
    pub min_samples_split: usize,
    pub criterion: T,
}

impl<R: Rng, T: Criterion> NodeBuilder<R, T> {
    pub fn build(&mut self, table: &mut Table, depth: usize) -> Node {
        if table.rows_len() < self.min_samples_split || depth > self.max_depth {
            let value = self.average(table.target());
            return Node::Leaf(value);
        }

        let impurity = self.criterion.calculate(table.target());
        let valid_columns = (0..table.features_len())
            .filter(|&i| !table.column(i).any(|f| f.is_nan()))
            .collect::<Vec<_>>();

        let mut best_split: Option<SplitPoint> = None;
        let mut best_information_gain = f64::MIN;
        let max_features = std::cmp::min(valid_columns.len(), self.max_features);
        for &column in valid_columns.choose_multiple(&mut self.rng, max_features) {
            table.sort_rows_by_column(column);
            for (left_row, value) in table.split_points(column) {
                let rows_l = table.target().take(left_row.end).skip(left_row.start);
                let rows_r = table.target().take(left_row.start).chain(table.target().skip(left_row.end));
                let impurity_l = self.criterion.calculate(rows_l);
                let impurity_r = self.criterion.calculate(rows_r);
                let ratio_l = (left_row.end - left_row.start) as f64 / table.rows_len() as f64;
                let ratio_r = 1.0 - ratio_l;

                let information_gain = impurity - (ratio_l * impurity_l + ratio_r * impurity_r);
                if best_information_gain < information_gain {
                    best_information_gain = information_gain;
                    best_split = Some(SplitPoint { column, value });
                }
            }
        }

        if let Some(split) = best_split {
            table.sort_rows_by_column(split.column);
            let split_row = table.column(split.column).take_while(|&f| f <= split.value).count();
            let (left, right) = table.with_split(split_row, |table| {
                Box::new(self.build(table, depth + 1))
            });

            Node::Children { split, left, right }
        } else {
            Node::Leaf(self.average(table.target()))
        }
    }

    fn average(&self, ys: impl Iterator<Item = f64>) -> f64 {
        match self.criterion.criterion_type() {
            CriterionType::Regression => mean(ys),
            CriterionType::Classification => most_frequent(ys),
        }
    }
}
