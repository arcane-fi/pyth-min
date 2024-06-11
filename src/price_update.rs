use crate::{
    byte_utils::PubkeyBytes,
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

    /// Get a `VerificationLevel` from bytes. Expects exactly one byte.
    /// The first byte indicates the verification level type:
    /// * 0x00 for `Partial`, followed by the number of signatures as the second byte.
    /// * 0x01 for `Full`, with no additional bytes required.
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
    pub fn get_price_unchecked(&self, feed_id: &FeedId) -> Result<Price, GetPriceError> {
        if self.price_message.feed_id != *feed_id {
            return Err(GetPriceError::MismatchedFeedId);
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
        feed_id: &FeedId,
        verification_level: VerificationLevel,
    ) -> Result<Price, GetPriceError> {
        if !self.verification_level.gte(verification_level) {
            return Err(GetPriceError::InsufficientVerificationLevel);
        };

        let price = self.get_price_unchecked(feed_id)?;
        if !price
            .publish_time
            .saturating_add(maximum_age.try_into().unwrap())
            >= unix_timestamp
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
        feed_id: &FeedId,
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
    // 1-byte verification level enum
    // 01
    // TODO if this is partial, does it become two bytes?
    //
    // 32-byte feed ID:
    // 0    2    4    6    8    10   12   14   16   18   20   22   24   26   28   30
    // ef0d 8b6f da2c eba4 1da1 5d40 95d1 da39 2a0d 2f8e d0c6 c7bc 0f4c fac8 c280 b56d

    #[test]
    fn verification_from_bytes() {
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
}
