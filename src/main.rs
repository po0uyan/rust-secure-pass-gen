mod cli;
mod password_generator;
mod word;
mod test;
use crate::cli::cleanup_listener_on_signal_or_timeout;
pub use crate::cli::PasswordGeneratorConfig;
use clap::Parser;
use cli::fail_on_non_tty;
use password_generator::{
    base::{PassGenerator, PassGeneratorStrategy},
    memorable::MemorablePassGenerator,
    pin::PinPassGenerator,
    random::RandomPassGenerator,
};

fn main() {
    let confs: PasswordGeneratorConfig = PasswordGeneratorConfig::parse();
    cleanup_listener_on_signal_or_timeout(|| {
        let generator_strategy = extract_pass_generate_type(&confs);
        let mut pass_generator = PassGenerator::new(generator_strategy);
        fail_on_non_tty(confs.insecure_mode);
        pass_generator.generate();
    });
}

fn extract_pass_generate_type(confs: &PasswordGeneratorConfig) -> Box<dyn PassGeneratorStrategy> {
    match &confs.gen_type[0..] {
        "random" => Box::new(RandomPassGenerator::new(confs)),
        "pin" => Box::new(PinPassGenerator::new(confs)),
        "memorable" => Box::new(MemorablePassGenerator::new(confs)),
        _ => Box::new(RandomPassGenerator::new(confs)),
    }
}
