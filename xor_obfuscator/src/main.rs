use xor_obfuscator::{xor, Key};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        println!("!! Error !!");
        println!("Usage: <path/to/data> <key>");
        std::process::exit(1);
    }
    let data = std::fs::read(&args[1]).expect("Error reading file");
    let key_string = &args[2];
    let key = Key::new(key_string);
    let encoded_data = xor(data.as_slice(), &key);
    println!("Encoded data:\n{:?}", encoded_data);
}
