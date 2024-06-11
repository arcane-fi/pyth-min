pub mod messages;
pub mod byte_utils;
pub mod price_update;
pub mod error;

pub(crate) type Pubkey = [u8; 32];

/// Official Message Buffer Program Id
/// pubkey!("7Vbmv1jt4vyuqBZcpYPpnVhrqVe5e6ZPb6JxDcffRHUM");
pub const MESSAGE_BUFFER_PID: Pubkey = [
    96, 121, 180, 39, 141, 35, 152, 85, 128, 70, 147, 124, 128, 196, 115, 241, 86, 159, 207, 148,
    39, 234, 137, 86, 178, 4, 238, 48, 102, 178, 128, 18,
];

/// Pubkey::find_program_address(&[b"emitter"], &sysvar::accumulator::id());
/// pubkey!("G9LV2mp9ua1znRAfYwZz5cPiJMAbo1T6mbjdQsDZuMJg");
pub const ACCUMULATOR_EMITTER_ADDRESS: Pubkey = [
    225, 1, 250, 237, 172, 88, 81, 227, 43, 155, 35, 181, 249, 65, 26, 140, 43, 172, 74, 174, 62,
    212, 221, 123, 129, 29, 209, 167, 46, 164, 170, 113,
];

/// Official Program IDs and Addresses on Pythnet
pub mod pythnet {
    use super::Pubkey;
    /// Official Wormhole Program Address on Pythnet
    /// pubkey!("H3fxXJ86ADW2PNuDDmZJg6mzTtPxkYCpNuQUTgmJ7AjU");
    pub const WORMHOLE_PID: Pubkey = [
        238, 106, 51, 154, 165, 236, 145, 158, 20, 176, 156, 210, 101, 132, 136, 107, 95, 235, 248,
        189, 230, 34, 185, 117, 208, 26, 214, 142, 191, 11, 208, 35,
    ];

    /// Pubkey::find_program_address(&[b"Sequence", &emitter_pda_key.to_bytes()], &WORMHOLE_PID);
    /// pubkey!("8MuVR15V86sSELdpW4UYTyx7WTXRARF1Bj7GJHgTJP3K");
    pub const ACCUMULATOR_SEQUENCE_ADDR: Pubkey = [
        109, 92, 198, 114, 10, 119, 5, 31, 13, 197, 193, 195, 132, 17, 12, 3, 77, 111, 158, 247,
        194, 137, 236, 50, 8, 185, 1, 61, 85, 94, 54, 198,
    ];

    /// Official Pyth Oracle Program Id on Pythnet
    /// pubkey!("FsJ3A3u2vn5cTVofAjvy6y5kwABJAqYWpe4975bi2epH");
    pub const PYTH_PID: Pubkey = [
        220, 229, 235, 225, 228, 156, 59, 159, 17, 76, 181, 84, 76, 80, 169, 158, 192, 214, 146,
        214, 63, 86, 121, 90, 224, 41, 172, 131, 217, 234, 139, 226,
    ];
}