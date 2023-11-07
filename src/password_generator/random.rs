use rand::{distributions::Uniform, prelude::Distribution, thread_rng, Rng};
use secrecy::{SecretString, Zeroize};

use crate::PasswordGeneratorConfig;

use super::base::PassGeneratorStrategy;

const CHARSET: [&[u8]; 4] = [
    b"abcdefghijklmnopqrstuvwxyz",
    b"0123456789",
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    b")(*&^%$-#@!~+",
];

pub struct RandomPassGenerator {
    password: SecretString,
    config_mask: u8,
    length: u16,
}

impl RandomPassGenerator {
    pub fn new(config: &PasswordGeneratorConfig) -> Self {
        RandomPassGenerator {
            password: SecretString::new(String::with_capacity(config.length as usize)),
            config_mask: generate_mask(&[
                true,
                config.use_numbers,
                config.use_capitals,
                config.use_symbols,
            ]),
            length: config.length,
        }
    }
}

impl PassGeneratorStrategy for RandomPassGenerator {
    fn generate_password(&mut self) {
        let char_type_distribution: Uniform<u8> = Uniform::new_inclusive(0, 3);
        let mut rng = thread_rng();
        let mut sample_chars: Vec<char> = Vec::new();
        while sample_chars.len() != self.length.into() {
            let mut set_idx = char_type_distribution.sample(&mut rng);
            if self.config_mask & (1 << set_idx) != 0 {
                let mut idx = rng.gen_range(0..CHARSET[set_idx as usize].len());
                sample_chars.push(CHARSET[set_idx as usize][idx] as char);
                idx.zeroize();
                set_idx.zeroize();
            }
        }
        self.set_password_safe(sample_chars.iter().collect::<String>());
        sample_chars.zeroize();
    }

    fn calculate_entropy(&self) -> f64 {
        let mut possible_outcomes: f64 = 0.0;
        for i in 0..CHARSET.len() {
            if self.config_mask & (1 << i) != 0 {
                possible_outcomes += CHARSET[i].len() as f64;
            }
        }
        self.length as f64 * f64::log2(possible_outcomes)
    }

    fn get_password_safe(&self) -> &SecretString {
        &self.password
    }

    fn set_password_safe(&mut self, password: String) {
        self.password = SecretString::from(password);
    }
}

pub fn generate_mask(conditions: &[bool; 4]) -> u8 {
    let mut mask = 0;

    for (index, &condition) in conditions.iter().enumerate() {
        if condition {
            mask |= 1 << index;
        }
    }

    mask
}
