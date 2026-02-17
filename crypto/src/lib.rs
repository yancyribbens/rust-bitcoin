// SPDX-License-Identifier: CC0-1.0

//! # Rust Bitcoin Cryptography

#![no_std]
// Experimental features we need.
#![doc(test(attr(warn(unused))))]
// Coding conventions.
#![warn(deprecated_in_future)]
#![warn(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

/// Re-export the `hex-conservative` crate.
pub extern crate hex_stable as hex;

#[cfg(feature = "alloc")]
pub mod ecdsa;
#[cfg(feature = "alloc")]
pub mod key;
#[cfg(feature = "alloc")]
pub mod sighash;

#[cfg(feature = "alloc")]
include!("../include/newtype.rs"); // Explained in `REPO_DIR/docs/README.md`.
