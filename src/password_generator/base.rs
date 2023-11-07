use console::Term;
use regex::Regex;
use secrecy::{ExposeSecret, SecretString};
pub trait PassGeneratorStrategy {
    fn generate_password(&mut self);
    fn calculate_entropy(&self) -> f64;
    fn get_password_safe(&self) -> &SecretString;
    fn set_password_safe(&mut self, password: String);
    fn calculate_strength(&self) -> f64 {
        let password = self.get_password_safe();
        let rules = vec![
            (r".{8,}", 5.0),
            (r"(.*[a-z].*)", 5.0),
            (r"(.*[A-Z].*)", 5.0),
            (r"(.*\d.*)", 5.0),
            (r"(.*[!@#$%^&*()_+\-=\[\]{};:\'\\|,.\/?~].*)", 10.0),
        ];

        let mut score = 0.0;
        for (pattern, weight) in &rules {
            let re = Regex::new(pattern).unwrap();
            if re.is_match(password.expose_secret()) {
                score += weight;
            }
        }

        // Normalize the score
        let max_score = rules.iter().map(|(_, weight)| weight).sum::<f32>();
        let percentage = (score / max_score) * 100.0;

        percentage as f64
    }
    fn output_pass_strength(&self) {
        let strength_output = format!(
            "Shannon entropy: {:.2}\nStrength: {:.2}",
            self.calculate_entropy(),
            self.calculate_strength(),
        );
        let term = Term::stderr();
        term.write_line(&strength_output).unwrap();
    }
    fn output_pass(&self) {
        let term = Term::stdout();
        term.write_line(self.get_password_safe().expose_secret())
            .unwrap();
    }
}

pub struct PassGenerator {
    generation_strategy: Box<dyn PassGeneratorStrategy>,
}

impl PassGenerator {
    pub fn new(generation_strategy: Box<dyn PassGeneratorStrategy>) -> Self {
        PassGenerator {
            generation_strategy,
        }
    }
    pub fn generate(&mut self) {
        self.generation_strategy.generate_password();
        self.generation_strategy.output_pass_strength();
        self.generation_strategy.output_pass();
    }
}
