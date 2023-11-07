# Rust CLI Password Generator

## Overview

This Project is a secure CLI password generator written in rust.\
This will generate a secure password along with shannon entropy and an intuitive password strength.

## Build and Run Instructions

### Build

- First make sure you have the rust toolchain installed using rustup.
- You can build the binary by running `cargo build --release` to build the project.
- You can run the project by running the output binary `./target/release/pass-gen`.
- Optional: You can copy and paste `./target/release/pass-gen` into your `/usr/local/bin/` if you are on the UNIX based environment. Then just run `pass-gen`.

### Usage Instructions

```bash
Usage: pass-gen [OPTIONS]

Options:
  -l, --length <LENGTH>
          Password length to be generated [default: 8]
  -g, --gen-type <GEN_TYPE>
          Password generation mechanism to be used [default: random] [possible values: random, pin, memorable]
  -n, --use-numbers
          Whether to use numbers in password
  -s, --use-symbols
          Whether to use special symbols in password
  -c, --use-capitals
          Whether to use capitalized letters in password
  -k, --capitalize-memorable-words
          Whether to capitalize generated words by chance
  -t, --capitalize-memorable-first-letter
          Whether to capitalize the first letter of generated words by chance
  -w, --words-count <WORDS_COUNT>
          The number of words included in memorable password [default: 5]
      --insecure-mode
          Run in insecure mode. The output can be redirected or piped to files or non terminal environments
  -h, --help
          Print help
  -V, --version
          Print version
```

An example output would be as follows for `pass-gen -n -s -c -l 19` prompt:

```

Shannon entropy: 118.35
Strength: 100.00
z67r81kNk*v~&ud5gjT
Hit Enter to exit
```

Or we can have a memorable password with 4 words in it by running `pass-gen -g memorable -w 4` prompt:

```
Shannon entropy: 51.70
Strength: 66.67
unwired-hungrily-spirited-encrypt
Hit Enter to exit
```

## Development Perspective

### Project Structure

This Project has three parts including `main`,`cli`,`password_generator`.
Strategy pattern has been used in `password_generator`, to generate `Random`,`Memorable`, and `Pin` passwords.
There is an `assets` directory which holds the EFF word list for diceware generation.

### Testing

- Run tests by running `cargo test` to run through the test cases. 

## Security Perspective

### Data Protection

- Secrecy crate has been used to `Zeroise` the memory. This crates guarantees that the memory will be freed.\
- It has been made sure that Secret types won't log anywhere by chance as they are protected by Secret type.
- Running this program on a non-tty environment has been prohibited to prevent logging non-deliberately or letting malicious softwares sniff the generated password.
- The output will be dismissed and overwritten after a timeout or any SIG from the OS.

### Vulnerabilities and Mitigation

This code is not using `mlock` and/or `mprotect` to prevent the os from dumping the data into disk on various scenarios on OS.

## Todo

- [ ] Write more tests with more coverage.
- [ ] More tests should be implemented in the future. Including security tests.
- [ ] Use Bolero along with a fuzzy engine to produce arbitrary configs for pass generators.
- [ ] Implement `mlock/mprotect` to protect the memory.

## License

MIT License.

## Contribution

Feel free to enhance this project by forking it and create a PR.
Leave a start if you find this useful.
