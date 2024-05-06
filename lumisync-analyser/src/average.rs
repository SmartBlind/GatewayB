use std::collections::VecDeque;

pub struct WeightedMovingAverage {
    buffer: VecDeque<f32>,
    total_weight: f32,
    capacity: usize,
}

impl WeightedMovingAverage {
    fn new(size: usize) -> Self {
        Self {
            buffer: VecDeque::with_capacity(size),
            total_weight: 0.0,
            capacity: size,
        }
    }

    fn update(&mut self, input: f32) -> f32 {
        if self.buffer.len() == self.capacity {
            self.total_weight -= self.buffer.pop_front().unwrap() * self.capacity as f32;
        }
        self.buffer.push_back(input);
        self.total_weight += input * self.buffer.len() as f32;

        self.total_weight / (self.buffer.len() * (self.buffer.len() + 1) / 2) as f32
    }
}
