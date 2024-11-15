use crate::{
    byte_utils::{interpret_bytes_as_u64, PubkeyBytes},
    error::GetPriceError,
    messages::{FeedId, PriceFeedMessage},
};

/// Pyth price updates are bridged to all blockchains via Wormhole.
/// Using the price updates on another chain requires verifying the signatures of the Wormhole guardians.
/// The usual process is to check the signatures for two thirds of the total number of guardians, but this can be cumbersome on Solana because of the transaction size limits,
/// so we also allow for partial verification.
///
/// This enum represents how much a price update has been verified:
/// - If `Full`, we have verified the signatures for two thirds of the current guardians.
/// - If `Partial`, only `num_signatures` guardian signatures have been checked.
///
/// # Warning
/// Using partially verified price updates is dangerous, as it lowers the threshold of guardians that need to collude to produce a malicious price update.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum VerificationLevel {
    Partial { num_signatures: u8 },
    Full,
}

impl VerificationLevel {
    /// Compare two `VerificationLevel`.
    /// `Full` is always greater than `Partial`, and `Partial` with more signatures is greater than `Partial` with fewer signatures.
    pub fn gte(&self, other: VerificationLevel) -> bool {
        match self {
            VerificationLevel::Full => true,
            VerificationLevel::Partial { num_signatures } => match other {
                VerificationLevel::Full => false,
                VerificationLevel::Partial {
                    num_signatures: other_num_signatures,
                } => *num_signatures >= other_num_signatures,
            },
        }
    }

    /// Get a `VerificationLevel` from bytes. Expects exactly one or two bytes.
    /// The first byte indicates the verification level type:
    /// * 0x00 for `Partial`, followed by the number of signatures as the second byte.
    /// * 0x01 for `Full`, with no additional bytes required.
    ///
    /// If the VerificationLevel level is Full, this will be one byte. If Partial, two bytes.
    pub fn get_verification_from_bytes(v: &[u8]) -> VerificationLevel {
        assert!(v.len() == 1 || v.len() == 2);
        match v.get(0).unwrap() {
            0x01 => VerificationLevel::Full,
            0x00 => {
                let num_signatures = *v.get(1).unwrap();
                VerificationLevel::Partial { num_signatures }
            }
            _ => panic!("invalid enum discrim"),
        }
    }
}

#[derive(Copy, Clone, PartialEq, Debug)]
pub struct PriceUpdateV2 {
    pub write_authority: PubkeyBytes,
    pub verification_level: VerificationLevel,
    pub price_message: PriceFeedMessage,
    pub posted_slot: u64,
}

/// A Pyth price.
/// The actual price is `(price ± conf)* 10^exponent`. `publish_time` may be used to check the recency of the price.
#[derive(PartialEq, Debug, Clone, Copy)]
pub struct Price {
    pub price: i64,
    pub conf: u64,
    pub exponent: i32,
    pub publish_time: i64,
}

impl PriceUpdateV2 {
    pub const LEN: usize = 8 + 32 + 2 + 32 + 8 + 8 + 4 + 8 + 8 + 8 + 8 + 8;

    /// Interpret a PriceUpdateV2 from a byte slice
    ///
    /// If you have fetched a "Price Feed Account" on chain, you probably want to get the data with
    ///
    /// `let data = &ctx.accounts.price.try_borrow_data()?[..];`
    ///
    /// Skip the first 8 bytes (Anchor discriminator)
    ///
    /// `let message_bytes = &data[8..];`
    pub fn get_price_update_v2_from_bytes(v: &[u8]) -> PriceUpdateV2 {
        // assert!(v.len() == PriceUpdateV2::LEN);

        let write_authority: PubkeyBytes = {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&v[0..32]);
            arr
        };
        // If VerificationLevel::Full (0x01) then only one byte is used, otherwise 2 bytes.
        let verification_one_byte = v[32] == 0x01;

        let verification_level = if verification_one_byte {
            VerificationLevel::get_verification_from_bytes(&v[32..33])
        } else {
            VerificationLevel::get_verification_from_bytes(&v[32..34])
        };

        let price_message = if verification_one_byte {
            PriceFeedMessage::get_feed_from_bytes(&v[33..117])
        } else {
            PriceFeedMessage::get_feed_from_bytes(&v[34..118])
        };

        let posted_slot = if verification_one_byte {
            interpret_bytes_as_u64(&v[117..125])
        } else {
            interpret_bytes_as_u64(&v[118..126])
        };

        PriceUpdateV2 {
            write_authority,
            verification_level,
            price_message,
            posted_slot,
        }
    }
}

impl PriceUpdateV2 {
    /// Get a `Price` from a `PriceUpdateV2` account for a given `FeedId`.
    ///
    /// # Warning
    /// This function does not check :
    /// - How recent the price is
    /// - Whether the price update has been verified
    ///
    /// It is therefore unsafe to use this function without any extra checks, as it allows for the possibility of using unverified or outdated price updates.
    pub fn get_price_unchecked(&self, feed_id: Option<&FeedId>) -> Result<Price, GetPriceError> {
        if feed_id.is_some() {
            if self.price_message.feed_id != *feed_id.unwrap() {
                return Err(GetPriceError::MismatchedFeedId);
            }
        }

        Ok(Price {
            price: self.price_message.price,
            conf: self.price_message.conf,
            exponent: self.price_message.exponent,
            publish_time: self.price_message.publish_time,
        })
    }

    /// Get a `Price` from a `PriceUpdateV2` account for a given `FeedId` no older than
    /// `maximum_age` with customizable verification level.
    ///
    /// # Warning
    /// Lowering the verification level from `Full` to `Partial` increases the risk of using a
    /// malicious price update. Please read the documentation for [`VerificationLevel`] for more
    /// information.
    ///
    /// # Example
    /// ```
    /// use pyth_solana_receiver_sdk::price_update::{get_feed_id_from_hex, VerificationLevel, PriceUpdateV2};
    /// use anchor_lang::prelude::*;
    ///
    /// const MAXIMUM_AGE : u64 = 30;
    /// const FEED_ID: &str = "0xef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d"; // SOL/USD
    ///
    /// #[derive(Accounts)]
    /// #[instruction(amount_in_usd : u64)]
    /// pub struct ReadPriceAccount<'info> {
    ///     pub price_update: Account<'info, PriceUpdateV2>,
    /// }
    ///
    /// pub fn read_price_account(ctx : Context<ReadPriceAccount>) -> Result<()> {
    ///     let price_update = &mut ctx.accounts.price_update;
    ///     let price = price_update.get_price_no_older_than_with_custom_verification_level(&Clock::get()?.unix_timestamp, MAXIMUM_AGE, &get_feed_id_from_hex(FEED_ID)?, VerificationLevel::Partial{num_signatures: 5})?;
    ///     Ok(())
    /// }
    ///```
    pub fn get_price_no_older_than_with_custom_verification_level(
        &self,
        unix_timestamp: i64,
        maximum_age: u64,
        feed_id: Option<&FeedId>,
        verification_level: VerificationLevel,
    ) -> Result<Price, GetPriceError> {
        if !self.verification_level.gte(verification_level) {
            return Err(GetPriceError::InsufficientVerificationLevel);
        };

        let price = self.get_price_unchecked(feed_id)?;
        if !(price
            .publish_time
            .saturating_add(maximum_age.try_into().unwrap())
            >= unix_timestamp)
        {
            return Err(GetPriceError::PriceTooOld);
        }

        Ok(price)
    }

    /// Get a `Price` from a `PriceUpdateV2` account for a given `FeedId` no older than `maximum_age` with `Full` verification.
    ///
    /// # Example
    /// ```
    /// use pyth_solana_receiver_sdk::price_update::{get_feed_id_from_hex, PriceUpdateV2};
    /// use anchor_lang::prelude::*;
    ///
    /// const MAXIMUM_AGE : u64 = 30;
    /// const FEED_ID: &str = "0xef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d"; // SOL/USD
    ///
    /// #[derive(Accounts)]
    /// #[instruction(amount_in_usd : u64)]
    /// pub struct ReadPriceAccount<'info> {
    ///     pub price_update: Account<'info, PriceUpdateV2>,
    /// }
    ///
    /// pub fn read_price_account(ctx : Context<ReadPriceAccount>) -> Result<()> {
    ///     let price_update = &mut ctx.accounts.price_update;
    ///     let price = price_update.get_price_no_older_than(&Clock::get()?.unix_timestamp, MAXIMUM_AGE, &get_feed_id_from_hex(FEED_ID)?)?;
    ///     Ok(())
    /// }
    ///```
    pub fn get_price_no_older_than(
        &self,
        unix_timestamp: i64,
        maximum_age: u64,
        feed_id: Option<&FeedId>,
    ) -> std::result::Result<Price, GetPriceError> {
        self.get_price_no_older_than_with_custom_verification_level(
            unix_timestamp,
            maximum_age,
            feed_id,
            VerificationLevel::Full,
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::byte_utils::hex_to_bytes;

    use super::*;

    // Price V2 header
    // Note: Solana (and most explorers for it) use little-endian...
    // 8-byte anchor discriminator:
    // 22f1 2363 9d7e f4cd
    //
    // 32-byte write authority key:
    // 0    2    4    6    8    10   12   14   16   18   20   22   24   26   28   30
    // 6031 4704 340d eddf 371f d424 7214 8f24 8e9d 1a6d 1a5e b2ac 3acd 8b7f d5d6 b243
    //
    // 1 or 2-byte verification level enum
    // 01
    //
    // 32-byte feed ID:
    // 0    2    4    6    8    10   12   14   16   18   20   22   24   26   28   30
    // ef0d 8b6f da2c eba4 1da1 5d40 95d1 da39 2a0d 2f8e d0c6 c7bc 0f4c fac8 c280 b56d
    //
    // 52-bytes for the rest of the Price Feed Message:
    // price:                   107f c8e3 0300 0000
    // conf:                    49a7 5501 0000 0000
    // exponent:                f8ff ffff
    // publish time:            3149 6366 0000 0000
    // prev publish time:       3049 6366 0000 0000
    // ema price:               8cc4 27ed 0300 0000
    // ema conf:                9b14 0301 0000 0000
    #[test]
    fn verification_from_bytes_full() {
        // From mainnet: https://solana.fm/address/7UVimffxr9ow1uXYxsr4LHAcV58mLzhmwaeKvJ1pjLiE
        let hex_data = "22f123639d7ef4cd60314704340deddf371fd42472148f248e9d1a6d1a5eb2ac3acd8b7fd5d6b24301ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d107fc8e30300000049a7550100000000f8ffffff314963660000000030496366000000008cc427ed030000009b14030100000000dded1e100000000000";
        let bytes = hex_to_bytes(hex_data);

        // Skip the first 8 bytes (Anchor discriminator), the authority (32 bytes)
        let message_bytes = &bytes[40..41];
        println!("{:?}", message_bytes);

        let message = VerificationLevel::get_verification_from_bytes(message_bytes);
        println!("{:?}", message);

        assert_eq!(message, VerificationLevel::Full);
    }

    #[test]
    fn verification_from_bytes_partial() {
        // From devnet: https://solana.fm/address/DMzo13MxzhrU1dbtJRCxdLoa9zwWowBJu17KhRQ5tLWM
        let hex_data =  "22f123639d7ef4cd0d881b9f67c8cb3d52fd2eb27d13c20951d199212b75021d55ecbf5e183b8cdb0005ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d5eaf3497030000000e62e80000000000f8fffffffb4e686600000000fa4e686600000000f45b539503000000ae73de000000000011ce2d1200000000";
        let bytes = hex_to_bytes(hex_data);

        // Skip the first 8 bytes (Anchor discriminator), the authority (32 bytes)
        let message_bytes = &bytes[40..42];
        println!("{:?}", message_bytes);

        let message = VerificationLevel::get_verification_from_bytes(message_bytes);
        println!("{:?}", message);

        assert_eq!(message, VerificationLevel::Partial { num_signatures: 5 });
    }

    #[test]
    fn pricev2_from_bytes_full() {
        // From mainnet: https://solana.fm/address/7UVimffxr9ow1uXYxsr4LHAcV58mLzhmwaeKvJ1pjLiE
        let hex_data = "22f123639d7ef4cd60314704340deddf371fd42472148f248e9d1a6d1a5eb2ac3acd8b7fd5d6b24301ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d107fc8e30300000049a7550100000000f8ffffff314963660000000030496366000000008cc427ed030000009b14030100000000dded1e100000000000";
        let bytes = hex_to_bytes(hex_data);

        // Skip the first 8 bytes (Anchor discriminator)
        let message_bytes = &bytes[8..];
        println!("{:?}", message_bytes);

        let message = PriceUpdateV2::get_price_update_v2_from_bytes(message_bytes);
        println!("{:?}", message);

        // actual key: 7UVimffxr9ow1uXYxsr4LHAcV58mLzhmwaeKvJ1pjLiE
        let expected_write_authority: [u8; 32] = [
            96, 49, 71, 4, 52, 13, 237, 223, 55, 31, 212, 36, 114, 20, 143, 36, 142, 157, 26, 109,
            26, 94, 178, 172, 58, 205, 139, 127, 213, 214, 178, 67,
        ];
        assert_eq!(message.write_authority, expected_write_authority);
        assert_eq!(message.verification_level, VerificationLevel::Full);
        assert_eq!(message.price_message.price, 16706469648); // 107f c8e3 0300 0000 or bytes [6, 127, 200, 227, 3, 0, 0, 0]
        assert_eq!(message.price_message.conf, 22390601); // 49a7 5501 0000 0000 or bytes [73, 167, 85, 1, 0, 0, 0, 0]
        assert_eq!(message.price_message.exponent, -8); // f8ff ffff or bytes [248, 255, 255, 255]
        assert_eq!(message.price_message.publish_time, 1717782833); // 3149 6366 0000 0000 or bytes [49, 73, 99, 102, 0, 0, 0, 0]
        assert_eq!(message.price_message.prev_publish_time, 1717782832); // 3049 6366 0000 0000 or bytes [140, 196, 39, 237, 3, 0, 0, 0]
        assert_eq!(message.price_message.ema_price, 16863708300); // 8cc4 27ed 0300 0000 or bytes [155, 20, 3, 1, 0, 0, 0, 0]
        assert_eq!(message.price_message.ema_conf, 16979099); // 9b14 0301 0000 0000 or bytes [221, 237, 30, 16, 0, 0, 0, 0, 0]

        assert_eq!(message.posted_slot, 270462429); // dded 1e10 0000 0000
    }

    #[test]
    fn pricev2_from_bytes_partial() {
        // From mainnet: https://solana.fm/address/7UVimffxr9ow1uXYxsr4LHAcV58mLzhmwaeKvJ1pjLiE
        let hex_data = "22f123639d7ef4cd0d881b9f67c8cb3d52fd2eb27d13c20951d199212b75021d55ecbf5e183b8cdb0005ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d5eaf3497030000000e62e80000000000f8fffffffb4e686600000000fa4e686600000000f45b539503000000ae73de000000000011ce2d1200000000";
        let bytes = hex_to_bytes(hex_data);

        // Skip the first 8 bytes (Anchor discriminator)
        let message_bytes = &bytes[8..];
        println!("{:?}", message_bytes);

        let message = PriceUpdateV2::get_price_update_v2_from_bytes(message_bytes);
        println!("{:?}", message);

        // actual key: upg8KLALUN7ByDHiBu4wEbMDTC6UnSVFSYfTyGfXuzr
        let expected_write_authority: [u8; 32] = [
            13, 136, 27, 159, 103, 200, 203, 61, 82, 253, 46, 178, 125, 19, 194, 9, 81, 209, 153,
            33, 43, 117, 2, 29, 85, 236, 191, 94, 24, 59, 140, 219,
        ];
        assert_eq!(message.write_authority, expected_write_authority);
        assert_eq!(
            message.verification_level,
            VerificationLevel::Partial { num_signatures: 5 }
        );
        assert_eq!(message.price_message.price, 15421714270);
        assert_eq!(message.price_message.conf, 15229454);
        assert_eq!(message.price_message.exponent, -8);
        assert_eq!(message.price_message.publish_time, 1718111995);
        assert_eq!(message.price_message.prev_publish_time, 1718111994);
        assert_eq!(message.price_message.ema_price, 15390170100);
        assert_eq!(message.price_message.ema_conf, 14578606);

        assert_eq!(message.posted_slot, 304991761);
    }
}
