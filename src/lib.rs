//! Secrets recovery from split chunks according to the
//! [banana split protocol](https://github.com/paritytech/banana_split).
//!
//! This crate is `no_std` compatible in `default-features = false` mode.
//!
//! # Examples
//!```
//! # #[cfg(feature = "std")]
//! # {
//! use banana_recovery::{Share, ShareCollection};
//!
//! // Recovering Alice seed phrase, from 2 shares out of 3 existing.
//!
//! const ALICE_SEEDPHRASE: &str = "bottom drive obey lake curtain smoke basket hold race lonely fit walk";
//! const SCAN_A1: &str = "7b2276223a312c2274223a22416c6963652074726965732042616e616e6153706c697420616761696e222c2272223a322c2264223a223841666c74524d465a42425930326b3675457262364e747a375855364957796747764649444c4247566167542f6e7a5365507a55304e7a436e7175795975363765666634675462674564445542787671594f4d32557048326c6758544c673667583437546c694958554d66317562322f7675726c7479727769516b564e5636505158673d3d222c226e223a226f39446270426939723755574a484f726975444172523456726330564f6f336c227d";
//! const SCAN_A2: &str = "7b2276223a312c2274223a22416c6963652074726965732042616e616e6153706c697420616761696e222c2272223a322c2264223a223841752f61694a2b794343786f715a7843434d6e32312f426358675a4b4935316b55742b644a6d6f782f7255456c3434485149547a437055414a38516835635a302b7155717067554d76697161777238763671786d3959544f4e636e66667942774249693067634b576f776463776f31664270456b5176357757694358654f38486a773d3d222c226e223a226f39446270426939723755574a484f726975444172523456726330564f6f336c227d";
//! const PASSPHRASE_A: &str = "blighted-comprised-bucktooth-disjoin";
//!
//! // Initiate share collector.
//! let mut share_collection = ShareCollection::new();
//!
//! // Process share #1 QR code.
//! let share1 = Share::new(hex::decode(SCAN_A1).unwrap()).unwrap();
//!
//! // Add share #1 to collector.
//! share_collection.add_share(share1).unwrap();
//!
//! if let ShareCollection::InProgress(ref in_progress) = share_collection {
//!     // 1 share collected so far
//!     assert_eq!(in_progress.shares_now(), 1);
//!
//!     // minimim 2 shares are needed (info from share itself)
//!     assert_eq!(in_progress.shares_required(), 2);
//!
//!     // set title, identical for all shares in set (info from share itself)
//!     assert_eq!(in_progress.title(), "Alice tries BananaSplit again");
//! } else {
//!     panic!("Added 1 share out of required 2. Must be `InProgress` variant.")
//! }
//!
//! // Try adding same share #1 again. This would result in an error.
//! let share1_again = Share::new(hex::decode(SCAN_A1).unwrap()).unwrap();
//! assert!(
//!     share_collection.add_share(share1_again).is_err(),
//!     "Can not add the same share second time."
//! );
//!
//! // Process share #2 QR code.
//! let share2 = Share::new(hex::decode(SCAN_A2).unwrap()).unwrap();
//!
//! // Add share #2 to collector.
//! share_collection.add_share(share2).unwrap();
//!
//! if let ShareCollection::Ready(combined) = share_collection {
//!     // `SetCombined` could be processed to recover the secret.
//!     let alice_secret = combined.recover_with_passphrase(PASSPHRASE_A).unwrap();
//!     assert_eq!(alice_secret, ALICE_SEEDPHRASE);
//! } else {
//!     panic!("Added 2 different shares out of required 2. Must be `Ready` variant.")
//! }
//! # }
//! ```
#![no_std]
#![deny(missing_docs)]
#![deny(unused_crate_dependencies)]
#![deny(unused_results)]

#[macro_use]
extern crate alloc;

extern crate core;

#[cfg(feature = "std")]
extern crate std;

mod error;
mod shares;

#[cfg(test)]
mod tests;

pub use error::BananaError;
pub use shares::{SetCombined, SetInProgress, Share, ShareCollection};
