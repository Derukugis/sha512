use sha512::sha512;

fn main() {
    let data = b"what";
    let hash = sha512(data);
    println!("{:x?}", hash);
}
