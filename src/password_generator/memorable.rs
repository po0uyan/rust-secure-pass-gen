use rand::{distributions::Uniform, prelude::*, thread_rng};
use secrecy::{ExposeSecret, Secret, SecretString, Zeroize};

use crate::{
    word::{HashWords, WordList},
    PasswordGeneratorConfig,
};

use super::base::PassGeneratorStrategy;

pub struct MemorablePassGenerator {
    words_map: HashWords,
    password: SecretString,
    words_count: u16,
    whole_word_capitalization_possibility: bool,
    first_letter_capitalization_possibility: bool,
}
impl Zeroize for MemorablePassGenerator {
    fn zeroize(&mut self) {
        self.words_count.zeroize();
        self.whole_word_capitalization_possibility.zeroize();
        self.first_letter_capitalization_possibility.zeroize();
    }
}

impl MemorablePassGenerator {
    pub fn new(config: &PasswordGeneratorConfig) -> Self {
        MemorablePassGenerator {
            words_map: WordList::get_words_map().words_map,
            password: SecretString::new(String::with_capacity(4 * config.words_count as usize)), // 4 was average size
            words_count: config.words_count,
            whole_word_capitalization_possibility: config.capitalize_memorable_words,
            first_letter_capitalization_possibility: config.capitalize_memorable_first_letter,
        }
    }

    pub fn restyle_word_by_chance(&self, word: &mut SecretString) {
        if self.whole_word_capitalization_possibility && rand::random() {
            *word = SecretString::from(word.expose_secret().to_uppercase());
        }
        if self.first_letter_capitalization_possibility && rand::random() {
            *word = SecretString::from(
                word.expose_secret()
                    .to_owned()
                    .remove(0)
                    .to_uppercase()
                    .to_string()
                    + &word.expose_secret()[1..],
            );
        }
    }
}

impl PassGeneratorStrategy for MemorablePassGenerator {
    fn generate_password(&mut self) {
        let mut password = String::new();
        for _ in 0..self.words_count {
            if !password.is_empty() {
                password += "-";
            }
            let dice_ware_number = dice_ware_number_generator();
            let mut generated_word = SecretString::new(
                self.words_map
                    .get(dice_ware_number.expose_secret())
                    .expect("Provided diceware numbers are malformed")
                    .into(),
            );
            self.restyle_word_by_chance(&mut generated_word);

            password += generated_word.expose_secret();
        }
        self.set_password_safe(password);
    }

    fn calculate_entropy(&self) -> f64 {
        let set_length = self.words_map.len();
        let pool_of_uniqe_possibilities: i64 = self.first_letter_capitalization_possibility as i64
            + self.whole_word_capitalization_possibility as i64
            + 1;
        let entropy: f64 = self.words_count as f64
            * f64::log2(pool_of_uniqe_possibilities as f64 * set_length as f64);
        entropy
    }

    fn get_password_safe(&self) -> &SecretString {
        &self.password
    }

    fn set_password_safe(&mut self, password: String) {
        self.password = SecretString::from(password);
    }
}

pub fn dice_ware_number_generator() -> Secret<u32> {
    let mut result: Secret<u32> = Secret::from(0);
    let distribution = Uniform::new_inclusive(1, 6);
    let mut rng = thread_rng();
    for i in 0..5 {
        // Times of rolling 5 times by default
        result =
            Secret::from(result.expose_secret() + distribution.sample(&mut rng) * u32::pow(10, i));
    }
    return result;
}
