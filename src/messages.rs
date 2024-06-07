/// Id of a feed producing the message. One feed produces one or more messages.
pub type FeedId = [u8; 32];

/// The discrminator of Price Feed Accounts on mainnet
pub const DISCRIMINATOR_AS_HEX: &str = "22f12363";

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct PriceFeedMessage {
    pub feed_id: FeedId,
    pub price: i64,
    pub conf: u64,
    pub exponent: i32,
    /// The timestamp of this price update in seconds
    pub publish_time: i64,
    /// The timestamp of the previous price update. This field is intended to allow users to
    /// identify the single unique price update for any moment in time:
    /// for any time t, the unique update is the one such that prev_publish_time < t <= publish_time.
    ///
    /// Note that there may not be such an update while we are migrating to the new message-sending logic,
    /// as some price updates on pythnet may not be sent to other chains (because the message-sending
    /// logic may not have triggered). We can solve this problem by making the message-sending mandatory
    /// (which we can do once publishers have migrated over).
    ///
    /// Additionally, this field may be equal to publish_time if the message is sent on a slot where
    /// where the aggregation was unsuccesful. This problem will go away once all publishers have
    /// migrated over to a recent version of pyth-agent.
    pub prev_publish_time: i64,
    pub ema_price: i64,
    pub ema_conf: u64,
}

impl PriceFeedMessage {
    /// Interpret a PriceFeedMessage from a byte slice (which must be exactly 88 bytes long with no
    /// padding). This is useful if you want to read price/confidence with no checks for
    /// verification or how recent the update was.
    /// 
    /// If you have fetched a "Price Feed Account" on chain, you probably want to get the data with
    /// 
    /// `let data = &ctx.accounts.price.try_borrow_data()?[..];`
    /// 
    /// and you can extract this message by reading bytes 41-129. Skip the first 8 bytes (Anchor
    /// discriminator), the auhority (32 bytes), and the verification type (1 byte). The end of the
    /// message is also padding.
    /// 
    /// `let message_bytes = &data[41..129];`
    pub fn get_feed_from_bytes(v: &[u8]) -> PriceFeedMessage {
        assert!(v.len() == std::mem::size_of::<PriceFeedMessage>());

        let feed_id: FeedId = {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&v[0..32]);
            arr
        };
        let price = interpret_bytes_as_i64(&v[32..40]);
        let conf = interpret_bytes_as_u64(&v[40..48]);
        let exponent = interpret_bytes_as_i32(&v[48..52]);
        let publish_time = interpret_bytes_as_i64(&v[52..60]);
        let prev_publish_time = interpret_bytes_as_i64(&v[60..68]);
        let ema_price = interpret_bytes_as_i64(&v[68..76]);
        let ema_conf = interpret_bytes_as_u64(&v[76..84]);

        PriceFeedMessage {
            feed_id,
            price,
            conf,
            exponent,
            publish_time,
            prev_publish_time,
            ema_price,
            ema_conf,
        }
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_price_feed_message_from_bytes() {
        // From mainnet: https://solana.fm/address/7UVimffxr9ow1uXYxsr4LHAcV58mLzhmwaeKvJ1pjLiE
        let hex_data = "22f123639d7ef4cd60314704340deddf371fd42472148f248e9d1a6d1a5eb2ac3acd8b7fd5d6b24301ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d107fc8e30300000049a7550100000000f8ffffff314963660000000030496366000000008cc427ed030000009b14030100000000dded1e100000000000";
        let bytes = hex_to_bytes(hex_data);

        // Skip the first 8 bytes (Anchor discriminator), the authority (32 bytes), and the
        // verification type (1 byte). The end of the message is also padding.
        let message_bytes = &bytes[41..129];
        println!("{:?}", message_bytes);
        let raw_publish_time_bytes = &message_bytes[52..60];
        println!("Raw bytes for publish_time: {:?}", raw_publish_time_bytes);
        let interpreted_publish_time = interpret_bytes_as_i64(raw_publish_time_bytes);
        println!("Interpreted publish_time: {}", interpreted_publish_time);

        let message = PriceFeedMessage::get_feed_from_bytes(message_bytes);
        println!("{:?}", message);

        // Note that Solana (and most explorers for it) use little-endian...
        assert_eq!(message.price, 16706469648); // 107f c8e3 0300 0000 or bytes [6, 127, 200, 227, 3, 0, 0, 0]
        assert_eq!(message.conf, 22390601); // 49a7 5501 0000 0000 or bytes [73, 167, 85, 1, 0, 0, 0, 0]
        assert_eq!(message.exponent, -8); // f8ff ffff or bytes [248, 255, 255, 255]
        // NOTE if you tried to interpret the byte slice from a pointer 
        // (e.g. unsafe { &*(v.as_ptr() as *const PriceFeedMessage) 
        // then this part and beyond would fail due to padding issues
        assert_eq!(message.publish_time, 1717782833); // 3149 6366 0000 0000 or bytes [49, 73, 99, 102, 0, 0, 0, 0]
        assert_eq!(message.prev_publish_time, 1717782832);
        assert_eq!(message.ema_price, 16863708300);
        assert_eq!(message.ema_conf, 16979099);
    }
}
