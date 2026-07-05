#[cfg(test)]
mod tests {
    use crate::{
        PasswordGeneratorConfig,
        password_generator::{
            base::{PassGeneratorStrategy, SafePassword, wipe},
            memorable::MemorablePassGenerator,
            random::RandomPassGenerator,
        },
    };

    fn config(gen_type: &str) -> PasswordGeneratorConfig {
        PasswordGeneratorConfig {
            length: 9,
            gen_type: gen_type.to_string(),
            use_numbers: true,
            use_symbols: true,
            use_capitals: true,
            capitalize_memorable_words: false,
            capitalize_memorable_first_letter: false,
            words_count: 3,
            insecure_mode: false,
        }
    }

    #[test]
    fn memorable_operates() {
        let confs = config("memorable");
        let mut memorable = MemorablePassGenerator::new(&confs);
        let pass = memorable.generate_password();
        assert_eq!(
            pass.split('-').count(),
            confs.words_count.into(),
            "Memorable type is returning correct number of words."
        );
        assert_eq!(
            memorable.calculate_entropy(),
            38.77443751081734,
            "Memorable entropy is returning correct entropy."
        );
    }

    #[test]
    fn random_operates() {
        let confs = config("random");
        let mut random = RandomPassGenerator::new(&confs);
        let pass = random.generate_password();
        assert_eq!(
            pass.len(),
            confs.length.into(),
            "random type is returning correct number of charecters."
        );
        assert_eq!(
            random.calculate_entropy(),
            56.05936821446292,
            "random entropy is returning correct entropy."
        );
    }

    #[test]
    fn safe_password_round_trips_through_protected_memory() {
        let mut safe = SafePassword::new(String::from("correct-horse-battery"));
        safe.with_str(|s| assert_eq!(s, "correct-horse-battery"));
        // The page reseals after each access; a second access must work.
        safe.with_str(|s| assert_eq!(s.len(), 21));
    }

    #[test]
    fn wipe_empties_working_buffers() {
        let mut s = String::from("transient-secret");
        let capacity = s.capacity();
        wipe(&mut s);
        assert!(s.is_empty());
        assert_eq!(s.capacity(), capacity, "wipe must not reallocate");
    }
}
