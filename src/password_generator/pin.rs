use rand::{distributions::Uniform, prelude::Distribution, thread_rng};
use secrecy::SecretString;

use crate::PasswordGeneratorConfig;

use super::base::PassGeneratorStrategy;

pub struct PinPassGenerator {
    password: SecretString,
    length: u16,
}

impl PinPassGenerator {
    pub fn new(config: &PasswordGeneratorConfig) -> Self {
        PinPassGenerator {
            password: SecretString::new(String::with_capacity(config.length as usize)),
            length: if config.length == 0 { 1 } else { config.length },
        }
    }
}

impl PassGeneratorStrategy for PinPassGenerator {
    fn generate_password(&mut self) {
        let mut password = String::with_capacity(self.length as usize);
        let distribution = Uniform::new_inclusive(0, 9);
        let mut rng = thread_rng();
        for _ in 0..self.length {
            password += &distribution.sample(&mut rng).to_string();
        }
        self.set_password_safe(password);
    }

    fn calculate_entropy(&self) -> f64 {
        self.length as f64 * f64::log2(10.0)
    }

    fn get_password_safe(&self) -> &SecretString {
        &self.password
    }

    fn set_password_safe(&mut self, password: String) {
        self.password = SecretString::from(password);
    }
}
