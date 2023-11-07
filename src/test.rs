#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use crate::{
        password_generator::{
            base::PassGeneratorStrategy, memorable::MemorablePassGenerator,
            random::RandomPassGenerator,
        },
        PasswordGeneratorConfig,
    };

    #[test]
    fn memorable_operates() {
        let confs = PasswordGeneratorConfig {
            length: 9,
            gen_type: "memorable".to_string(),
            use_numbers: false,
            use_symbols: false,
            use_capitals: false,
            capitalize_memorable_words: false,
            capitalize_memorable_first_letter: false,
            words_count: 3,
            insecure_mode: false,
        };
        let mut memorable = MemorablePassGenerator::new(&confs);
        memorable.generate_password();
        let pass = memorable.get_password_safe();
        assert_eq!(
            pass.expose_secret().split("-").collect::<Vec<&str>>().len(),
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
        let confs = PasswordGeneratorConfig {
            length: 9,
            gen_type: "random".to_string(),
            use_numbers: true,
            use_symbols: true,
            use_capitals: true,
            capitalize_memorable_words: false,
            capitalize_memorable_first_letter: false,
            words_count: 3,
            insecure_mode: false,
        };
        let mut random = RandomPassGenerator::new(&confs);
        random.generate_password();
        let pass = random.get_password_safe();
        assert_eq!(
            pass.expose_secret().len(),
            confs.length.into(),
            "random type is returning correct number of charecters."
        );
        assert_eq!(
            random.calculate_entropy(),
            56.05936821446292,
            "random entropy is returning correct entropy."
        );
    }
}
