use rand::{Rng, distributions::Uniform, prelude::Distribution, thread_rng};

use crate::PasswordGeneratorConfig;

use super::base::PassGeneratorStrategy;

const CHARSET: [&[u8]; 4] = [
    b"abcdefghijklmnopqrstuvwxyz",
    b"0123456789",
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    b")(*&^%$-#@!~+",
];

pub struct RandomPassGenerator {
    config_mask: u8,
    length: u16,
}

impl RandomPassGenerator {
    pub fn new(config: &PasswordGeneratorConfig) -> Self {
        RandomPassGenerator {
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
    fn generate_password(&mut self) -> String {
        // Characters go straight into a pre-sized String: no intermediate
        // collection to clean up, no reallocation leaving residue. The
        // sampling indices are plain integers that live in registers; the
        // password's page-level protection starts at ingestion.
        let char_type_distribution: Uniform<u8> = Uniform::new_inclusive(0, 3);
        let mut rng = thread_rng();
        let mut password = String::with_capacity(self.length as usize);
        while password.len() != self.length.into() {
            let set_idx = char_type_distribution.sample(&mut rng);
            if self.config_mask & (1 << set_idx) != 0 {
                let idx = rng.gen_range(0..CHARSET[set_idx as usize].len());
                password.push(CHARSET[set_idx as usize][idx] as char);
            }
        }
        password
    }

    fn calculate_entropy(&self) -> f64 {
        let mut possible_outcomes: f64 = 0.0;
        for (i, charset) in CHARSET.iter().enumerate() {
            if self.config_mask & (1 << i) != 0 {
                possible_outcomes += charset.len() as f64;
            }
        }
        self.length as f64 * f64::log2(possible_outcomes)
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
