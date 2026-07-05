use rand::{distributions::Uniform, prelude::*, thread_rng};

use crate::{
    word::{HashWords, WordList},
    PasswordGeneratorConfig,
};

use super::base::{wipe, PassGeneratorStrategy};

pub struct MemorablePassGenerator {
    words_map: HashWords,
    words_count: u16,
    whole_word_capitalization_possibility: bool,
    first_letter_capitalization_possibility: bool,
}

impl MemorablePassGenerator {
    pub fn new(config: &PasswordGeneratorConfig) -> Self {
        MemorablePassGenerator {
            words_map: WordList::get_words_map().words_map,
            words_count: config.words_count,
            whole_word_capitalization_possibility: config.capitalize_memorable_words,
            first_letter_capitalization_possibility: config.capitalize_memorable_first_letter,
        }
    }

    pub fn restyle_word_by_chance(&self, word: &mut String) {
        // Each restyling allocates a new String; swap it in and wipe the
        // buffer that held the previous form of the word.
        if self.whole_word_capitalization_possibility && rand::random() {
            let mut restyled = word.to_uppercase();
            std::mem::swap(word, &mut restyled);
            wipe(&mut restyled);
        }
        if self.first_letter_capitalization_possibility && rand::random() {
            if let Some(first) = word.get(0..1) {
                let mut restyled = first.to_uppercase() + &word[1..];
                std::mem::swap(word, &mut restyled);
                wipe(&mut restyled);
            }
        }
    }
}

impl PassGeneratorStrategy for MemorablePassGenerator {
    fn generate_password(&mut self) -> String {
        // Reserve generously up front: diceware words average ~6 chars, so
        // 16 per word (plus separator) means the buffer never reallocates
        // and leaves no partial copies behind.
        let mut password = String::with_capacity(self.words_count as usize * 16);
        for _ in 0..self.words_count {
            if !password.is_empty() {
                password.push('-');
            }
            let dice_ware_number = dice_ware_number_generator();
            let mut generated_word = self
                .words_map
                .get(&dice_ware_number)
                .expect("Provided diceware numbers are malformed")
                .clone();
            self.restyle_word_by_chance(&mut generated_word);
            password.push_str(&generated_word);
            wipe(&mut generated_word);
        }
        password
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
}

/// Roll five dice for a diceware lookup number. The number is an ephemeral
/// index into the public EFF word list; the word it selects is protected
/// from the moment the assembled password is ingested.
pub fn dice_ware_number_generator() -> u32 {
    let mut result: u32 = 0;
    let distribution = Uniform::new_inclusive(1, 6);
    let mut rng = thread_rng();
    for i in 0..5 {
        // Times of rolling 5 times by default
        result += distribution.sample(&mut rng) * u32::pow(10, i);
    }
    result
}
