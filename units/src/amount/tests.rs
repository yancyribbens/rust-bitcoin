// SPDX-License-Identifier: CC0-1.0

//! Unit tests for the `amount` module.

#[cfg(feature = "alloc")]
use alloc::format;
#[cfg(feature = "alloc")]
use alloc::string::{String, ToString};
#[cfg(feature = "std")]
use std::panic;

#[cfg(feature = "serde")]
use ::serde::{Deserialize, Serialize};

use super::*;
#[cfg(feature = "alloc")]
use crate::{FeeRate, Weight};

#[test]
fn tmp_amt {
}
