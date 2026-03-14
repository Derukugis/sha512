use sha512::{sha512_into, PaddedMessage};

fn main() {
    let data = b"what";

    let pl = PaddedMessage::pad_len(data.len());
    let mut pad = vec![0u8; pl];

    let hash = sha512_into(data, &mut pad);
    println!("{:x?}", hash);
}
