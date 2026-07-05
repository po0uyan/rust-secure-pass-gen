use console::Term;
use memsafe::Secret;
use regex::Regex;

/// Upper bound for a generated password. One protected page holds it
/// comfortably; the CLI caps its length arguments below this.
pub const MAX_PASSWORD_LEN: usize = 4096;

/// A generated password held in memsafe-protected memory: locked to RAM,
/// excluded from core dumps (Linux), sealed between accesses, and wiped on
/// drop. The `String` handed to `new` is volatile-zeroized during ingestion,
/// so no readable copy of the password outlives the handover.
pub struct SafePassword {
    bytes: Secret<MAX_PASSWORD_LEN>,
    len: usize,
}

impl SafePassword {
    pub fn new(password: String) -> Self {
        let len = password.len();
        let bytes = match Secret::<MAX_PASSWORD_LEN>::try_from(password) {
            Ok(secret) => secret,
            // No `expect` here: the error tuple carries the password back,
            // and Debug-formatting it would print the secret to stderr.
            Err((_password, err)) => {
                eprintln!("could not move the password into protected memory: {err}");
                std::process::exit(1);
            }
        };
        SafePassword { bytes, len }
    }

    /// Run `f` over the password while the protected page is readable.
    /// The page is sealed again before this returns.
    pub fn with_str<R>(&mut self, f: impl FnOnce(&str) -> R) -> R {
        let view = self
            .bytes
            .read()
            .expect("could not unseal protected memory");
        let s =
            std::str::from_utf8(&view[..self.len]).expect("generated passwords are valid UTF-8");
        f(s)
    }
}

/// Volatile-wipe a working string's buffer. For intermediates that held
/// password material before it reached protected memory; the volatile
/// writes cannot be optimized away.
pub fn wipe(s: &mut String) {
    unsafe {
        for b in s.as_mut_vec().iter_mut() {
            std::ptr::write_volatile(b, 0);
        }
    }
    s.clear();
}

pub trait PassGeneratorStrategy {
    /// Generate a password and hand it back as a raw `String`. The caller
    /// moves it straight into protected memory, which volatile-wipes this
    /// source buffer.
    fn generate_password(&mut self) -> String;
    fn calculate_entropy(&self) -> f64;
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
        let raw = self.generation_strategy.generate_password();
        // From here on the password lives in a locked, sealed page and the
        // `raw` buffer has been volatile-zeroized.
        let mut password = SafePassword::new(raw);
        self.output_pass_strength(&mut password);
        Self::output_pass(&mut password);
    }

    fn calculate_strength(password: &mut SafePassword) -> f64 {
        let rules = [
            (r".{8,}", 5.0),
            (r"(.*[a-z].*)", 5.0),
            (r"(.*[A-Z].*)", 5.0),
            (r"(.*\d.*)", 5.0),
            (r"(.*[!@#$%^&*()_+\-=\[\]{};:\'\\|,.\/?~].*)", 10.0),
        ];

        password.with_str(|pass| {
            let mut score = 0.0;
            for (pattern, weight) in &rules {
                let re = Regex::new(pattern).unwrap();
                if re.is_match(pass) {
                    score += weight;
                }
            }

            // Normalize the score
            let max_score = rules.iter().map(|(_, weight)| weight).sum::<f32>();
            let percentage = (score / max_score) * 100.0;

            percentage as f64
        })
    }

    fn output_pass_strength(&self, password: &mut SafePassword) {
        let strength_output = format!(
            "Shannon entropy: {:.2}\nStrength: {:.2}",
            self.generation_strategy.calculate_entropy(),
            Self::calculate_strength(password),
        );
        let term = Term::stderr();
        term.write_line(&strength_output).unwrap();
    }

    fn output_pass(password: &mut SafePassword) {
        password.with_str(|pass| {
            let term = Term::stdout();
            term.write_line(pass).unwrap();
        });
    }
}
