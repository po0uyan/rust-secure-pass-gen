use std::{process, sync::mpsc::channel, thread, time::Duration};

use atty::Stream;
use clap::Parser;
use console::Term;
const SECURITY_TIMEOUT: u64 = 7;
#[derive(Parser)]
#[command(author="pp", version, about, long_about = None)]
pub struct PasswordGeneratorConfig {
    #[arg(
        short,
        long,
        help = "Password length to be generated",
        allow_negative_numbers(false),
        requires_ifs([("random", "gen_type"),("pin", "gen_type")]),
        default_value_t = 8
    )]
    pub length: u16,
    #[arg(
        short,
        long,
        help = "Password generation mechanism to be used",
        value_parser(["random", "pin", "memorable"]),
        default_value_t=String::from("random")
    )]
    pub gen_type: String,

    #[arg(
        short = 'n',
        long,
        help = "Whether to use numbers in password",
        requires_if("random", "gen_type"),
        default_value_t = false
    )]
    pub use_numbers: bool,

    #[arg(
        short = 's',
        long,
        help = "Whether to use special symbols in password",
        requires_if("random", "gen_type"),
        default_value_t = false
    )]
    pub use_symbols: bool,

    #[arg(
        short = 'c',
        long,
        help = "Whether to use capitalized letters in password",
        requires_if("random", "gen_type"),
        default_value_t = false
    )]
    pub use_capitals: bool,

    #[arg(
        short = 'k',
        long,
        help = "Whether to capitalize generated words by chance",
        requires_if("memorable", "gen_type"),
        default_value_t = false
    )]
    pub capitalize_memorable_words: bool,

    #[arg(
        short = 't',
        long,
        help = "Whether to capitalize the first letter of generated words by chance",
        requires_if("memorable", "gen_type"),
        default_value_t = false
    )]
    pub capitalize_memorable_first_letter: bool,

    #[arg(
        short,
        long,
        help = "The number of words included in memorable password",
        allow_negative_numbers(false),
        default_value_t = 5,
        requires_if("memorable", "gen_type")
    )]
    pub words_count: u16,

    #[arg(
        long,
        help = "Run in insecure mode. The output can be redirected or piped to files or non terminal environments",
        default_value_t = false
    )]
    pub insecure_mode: bool,
}

pub fn cleanup_listener_on_signal_or_timeout<F>(f: F)
where
    F: Fn(),
{
    let cleanup = || {
        let term = Term::stdout();
        term.clear_last_lines(2).unwrap();
    };
    ctrlc::set_handler(move || {
        cleanup();
        process::exit(0);
    })
    .expect("Error setting Ctrl-C handler");

    let (sender, receiver) = channel();
    f();
    thread::spawn(move || {
        let term = Term::stdout();
        term.write_line("Hit Enter to exit").unwrap();
        term.read_line().unwrap();
        term.clear_last_lines(1).unwrap();
        sender.send("finished").unwrap();
    });

    let time = Duration::from_secs(SECURITY_TIMEOUT);
    receiver.recv_timeout(time).ok();
    cleanup();
}

pub fn fail_on_non_tty(insecure_mode: bool) -> () {
    if atty::isnt(Stream::Stdout) && !insecure_mode {
        eprintln!("This program is not allowed to be run on non tty environments.\nTo do so you need to set the insecure flag --insecure-mode .");
        process::exit(1);
    }
}
