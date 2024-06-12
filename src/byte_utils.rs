/// The discriminator of Price Feed Accounts on mainnet
pub const DISCRIMINATOR_AS_HEX: &str = "22f123639d7ef4cd";
pub const DISCRIMINATOR_AS_BYTES: &[i32; 8] = &[0x22, 0xF1, 0x23, 0x63, 0x9D, 0x7E, 0xF4, 0xCD];

/// Bytes that will be a Pubkey when decoded (this crate has dependencies and therefore does not
/// read Pubkeys)
pub type PubkeyBytes = [u8; 32];

/// A very minimal tool to convert a hex string like "22f123639" into the byte equivalent.
pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks(2)
        .map(|chunk| {
            let high = chunk[0] as char;
            let low = chunk[1] as char;
            let high = high.to_digit(16).expect("Invalid hex character") as u8;
            let low = low.to_digit(16).expect("Invalid hex character") as u8;
            (high << 4) | low
        })
        .collect()
}

/// A very minimal utility to interpret some bytes as an i64
pub fn interpret_bytes_as_i64(bytes: &[u8]) -> i64 {
    let mut arr = [0u8; 8];
    arr.copy_from_slice(bytes);
    i64::from_le_bytes(arr)
}

/// A very minimal utility to interpret some bytes as an i32
pub fn interpret_bytes_as_i32(bytes: &[u8]) -> i32 {
    let mut arr = [0u8; 4];
    arr.copy_from_slice(bytes);
    i32::from_le_bytes(arr)
}

/// A very minimal utility to interpret some bytes as an u64
pub fn interpret_bytes_as_u64(bytes: &[u8]) -> u64 {
    let mut arr = [0u8; 8];
    arr.copy_from_slice(bytes);
    u64::from_le_bytes(arr)
}