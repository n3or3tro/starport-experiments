// use rand::{thread_rng, Rng};
/// Demonstrate the use of xor decryption. This program should print
/// "println!("Hello, you can see me!");"
pub struct Key {
    pub key: String,
    // random offset to add entropy... i think xD
    // pub offset: u8,
}
impl Key {
    pub fn new(key: &str) -> Key {
        Key {
            key: match key.len() {
                0 => "default key".to_string(),
                _ => key.to_string(),
            },
            // offset: thread_rng().gen_range(0..255),
        }
    }
}

pub fn xor(data: &[u8], key: &Key) -> Vec<u8> {
    let mut key_index: usize = 0;
    let key_bytes = key.key.as_bytes();

    let mut res: Vec<u8> = Vec::new();
    for byte in data {
        res.push(byte ^ key_bytes[key_index]);
        // key_index = ((key_index + 1) + (key.offset as usize)) % key_bytes.len();
        key_index = (key_index + 1) % key_bytes.len();
    }
    return res;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor() {
        let key = Key::new("what the heeeeeeeelllllllllllll");
        let data = "Hello, you can see me!".as_bytes();
        let encrypted = xor(data, &key);
        let decrypted = xor(encrypted.as_slice(), &key);
        assert_eq!(data, decrypted);
        assert_ne!(data, encrypted);
        assert_ne!(encrypted, decrypted);
    }
}

// add the cfg attribute to the test module to only compile it when running tests
