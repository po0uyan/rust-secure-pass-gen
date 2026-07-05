use rand::{distributions::Uniform, prelude::Distribution, thread_rng};

use crate::PasswordGeneratorConfig;

use super::base::PassGeneratorStrategy;

pub struct PinPassGenerator {
    length: u16,
}

impl PinPassGenerator {
    pub fn new(config: &PasswordGeneratorConfig) -> Self {
        PinPassGenerator {
            length: if config.length == 0 { 1 } else { config.length },
        }
    }
}

impl PassGeneratorStrategy for PinPassGenerator {
    fn generate_password(&mut self) -> String {
        // Pre-sized so the buffer never reallocates; the caller wipes it
        // once the password is in protected memory.
        let mut password = String::with_capacity(self.length as usize);
        let distribution = Uniform::new_inclusive(0u8, 9);
        let mut rng = thread_rng();
        for _ in 0..self.length {
            password.push(char::from(b'0' + distribution.sample(&mut rng)));
        }
        password
    }

    fn calculate_entropy(&self) -> f64 {
        self.length as f64 * f64::log2(10.0)
    }
}
