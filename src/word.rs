use std::collections::HashMap;

pub const EFF_DATA_SET: &str = include_str!("../assets/eff_large_wordlist.txt");

pub type HashWords = HashMap<u32, String>;
#[derive(Clone, Debug)]
pub struct WordList {
    pub words_map: HashWords,
}

impl WordList {
    pub fn new(word_maps: HashWords) -> Self {
        if word_maps.is_empty() {
            panic!("List of words is empty.");
        }

        WordList {
            words_map: word_maps,
        }
    }

    pub fn load() -> Result<Self, WordListError<'static>> {
        let mut word_maps: HashWords = HashMap::new();
        EFF_DATA_SET
            .split_terminator("\n")
            .filter(|w| !w.is_empty())
            .for_each(|f| {
                let a = f.split(",").collect::<Vec<&str>>();
                word_maps.insert(a[0].parse().unwrap(), String::from(a[1]));
            });
        if word_maps.is_empty() {
            return Err(WordListError::Empty("The provide list was empty"));
        }
        Ok(Self::new(word_maps))
    }

    pub fn get_words_map() -> Self {
        match WordList::load() {
            Ok(words) => words,
            Err(WordListError::Empty(err)) => panic!("{:?}", err),
            Err(WordListError::IoError(err)) => panic!("Error while reading the file{:?}", err),
        }
    }
}
pub enum WordListError<'a> {
    Empty(&'a str),
    IoError(std::io::Error),
}
impl From<std::io::Error> for WordListError<'_> {
    fn from(err: std::io::Error) -> Self {
        WordListError::IoError(err)
    }
}
