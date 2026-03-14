use sha512::sha512;

fn main() {
    let data = b"what";
    let hash: String = sha512(data).iter().map(|b| format!("{:02x}", b)).collect();
    println!("{}", hash);
}
