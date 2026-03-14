use sha512::sha512;
use std::fs::File;
use std::io::{Read, BufReader};

fn main() {
    let file = File::open("examples/file.txt").unwrap();
    let mut reader = BufReader::new(file);
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer).unwrap();

    let hash = sha512(&buffer);
    println!("{:x?}", hash);
}
