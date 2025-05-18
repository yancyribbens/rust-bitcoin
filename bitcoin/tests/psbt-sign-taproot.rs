#![cfg(not(feature = "rand-std"))]

use std::collections::BTreeMap;

use bitcoin::bip32::{DerivationPath, Fingerprint};
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::opcodes::all::OP_CHECKSIG;
use bitcoin::psbt::{GetKey, Input, KeyRequest, PsbtSighashType, SignError};
use bitcoin::script::ScriptExt as _;
use bitcoin::taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo};
use bitcoin::transaction::Version;
use bitcoin::{
    absolute, script, Address, Network, OutPoint, PrivateKey, Psbt, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Witness,
};
use secp256k1::{Keypair, Secp256k1, Signing, XOnlyPublicKey};
use units::Amount;
