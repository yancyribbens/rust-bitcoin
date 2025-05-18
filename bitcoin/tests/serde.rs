//! Regression tests for _most_ types that implement `serde::Serialize`.
//!
//! For remaining types see: ./serde_opcodes.rs
//!
//! If you find a type defined in `rust-bitcoin` that implements `Serialize` and does _not_ have a
//! regression test please add it.
//!
//! Types/tests were found using, and are ordered by, the output of: `git grep -l Serialize`.
//!

// In tests below `deserialize` is consensus deserialize while `serialize` is serde serialize, that
// is why we have two different serialized data files for tests that use binary serialized input.
//
// To create a file with the expected serialized data do something like:
//
//  use std::fs::File;
//  use std::io::Write;
//  let script = ScriptBuf::from(vec![0u8, 1u8, 2u8]);
//  let got = serialize(&script).unwrap();
//  let mut file = File::create("/tmp/script_bincode").unwrap();
//  file.write_all(&got).unwrap();

#![cfg(feature = "serde")]

use std::collections::BTreeMap;

use bincode::serialize;
use bitcoin::bip32::{ChildNumber, KeySource, Xpriv, Xpub};
use bitcoin::consensus::encode::deserialize;
use bitcoin::hashes::{hash160, ripemd160, sha256, sha256d};
use bitcoin::hex::FromHex;
use bitcoin::locktime::{absolute, relative};
use bitcoin::psbt::raw::{self, Key, Pair, ProprietaryKey};
use bitcoin::psbt::{Input, Output, Psbt, PsbtSighashType};
use bitcoin::script::ScriptBufExt as _;
use bitcoin::sighash::{EcdsaSighashType, TapSighashType};
use bitcoin::taproot::{self, ControlBlock, LeafVersion, TapTree, TaprootBuilder};
use bitcoin::witness::Witness;
use bitcoin::{
    ecdsa, transaction, Address, Amount, Block, NetworkKind, OutPoint, PrivateKey, PublicKey,
    ScriptBuf, Sequence, Target, Transaction, TxIn, TxOut, Txid, Work,
};

/// Implicitly does regression test for `BlockHeader` also.
#[test]
fn serde_regression_block() {
    let segwit = include_bytes!(
        "data/testnet_block_000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b.raw"
    );
    let block: Block = deserialize(segwit).unwrap();
    let got = serialize(&block).unwrap();
    let want = include_bytes!("data/serde/block_bincode");
    assert_eq!(got, want)
}

#[test]
fn serde_regression_absolute_lock_time_height() {
    let t = absolute::LockTime::from_height(741521).expect("valid height");
    let got = serialize(&t).unwrap();
    let want = include_bytes!("data/serde/absolute_lock_time_blocks_bincode") as &[_];
    assert_eq!(got, want);
}

#[test]
fn serde_regression_absolute_lock_time_time() {
    let seconds: u32 = 1653195600; // May 22nd, 5am UTC.
    let t = absolute::LockTime::from_time(seconds).expect("valid time");
    let got = serialize(&t).unwrap();

    let want = include_bytes!("data/serde/absolute_lock_time_seconds_bincode") as &[_];
    assert_eq!(got, want);
}

#[test]
fn serde_regression_relative_lock_time_height() {
    let t = relative::LockTime::from(relative::Height::from(0xCAFE_u16));
    let got = serialize(&t).unwrap();

    let want = include_bytes!("data/serde/relative_lock_time_blocks_bincode") as &[_];
    assert_eq!(got, want);
}

#[test]
fn serde_regression_relative_lock_time_time() {
    let t = relative::LockTime::from(relative::Time::from_512_second_intervals(0xFACE_u16));
    let got = serialize(&t).unwrap();

    let want = include_bytes!("data/serde/relative_lock_time_seconds_bincode") as &[_];
    assert_eq!(got, want);
}

#[test]
fn serde_regression_script() {
    let script = ScriptBuf::from(vec![0u8, 1u8, 2u8]);
    let got = serialize(&script).unwrap();
    let want = include_bytes!("data/serde/script_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_txin() {
    let ser = include_bytes!("data/serde/txin_ser");
    let txin: TxIn = deserialize(ser).unwrap();

    let got = serialize(&txin).unwrap();
    let want = include_bytes!("data/serde/txin_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_txout() {
    let txout = TxOut { value: Amount::MAX, script_pubkey: ScriptBuf::from(vec![0u8, 1u8, 2u8]) };
    let got = serialize(&txout).unwrap();
    let want = include_bytes!("data/serde/txout_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_transaction() {
    let ser = include_bytes!("data/serde/transaction_ser");
    let tx: Transaction = deserialize(ser).unwrap();
    let got = serialize(&tx).unwrap();
    let want = include_bytes!("data/serde/transaction_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_witness() {
    let w0 = Vec::from_hex("03d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f2105")
        .unwrap();
    let w1 = Vec::from_hex("000000").unwrap();
    let vec = [w0, w1];
    let witness = Witness::from_slice(&vec);

    let got = serialize(&witness).unwrap();
    let want = include_bytes!("data/serde/witness_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_address() {
    let s = include_str!("data/serde/public_key_hex");
    let pk = s.trim().parse::<PublicKey>().unwrap();
    let addr = Address::p2pkh(pk, NetworkKind::Main);

    let got = serialize(&addr).unwrap();
    let want = include_bytes!("data/serde/address_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_extended_priv_key() {
    let s = include_str!("data/serde/extended_priv_key");
    let key = s.trim().parse::<Xpriv>().unwrap();
    let got = serialize(&key).unwrap();
    let want = include_bytes!("data/serde/extended_priv_key_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_extended_pub_key() {
    let s = include_str!("data/serde/extended_pub_key");
    let key = s.trim().parse::<Xpub>().unwrap();
    let got = serialize(&key).unwrap();
    let want = include_bytes!("data/serde/extended_pub_key_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_ecdsa_sig() {
    let s = include_str!("data/serde/ecdsa_sig_hex");
    let sig = ecdsa::Signature {
        signature: s.trim().parse::<secp256k1::ecdsa::Signature>().unwrap(),
        sighash_type: EcdsaSighashType::All,
    };

    let got = serialize(&sig).unwrap();
    let want = include_bytes!("data/serde/ecdsa_sig_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_control_block() {
    let s = include_str!("data/serde/control_block_hex");
    let block = ControlBlock::decode(&Vec::<u8>::from_hex(s.trim()).unwrap()).unwrap();
    let got = serialize(&block).unwrap();

    let want = include_bytes!("data/serde/control_block_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_child_number() {
    let num = ChildNumber::Normal { index: 0xDEADBEEF };
    let got = serialize(&num).unwrap();
    let want = include_bytes!("data/serde/child_number_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_private_key() {
    let sk = PrivateKey::from_wif("cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy").unwrap();
    let got = serialize(&sk).unwrap();
    let want = include_bytes!("data/serde/private_key_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_public_key() {
    let s = include_str!("data/serde/public_key_hex");
    let pk = s.trim().parse::<PublicKey>().unwrap();
    let got = serialize(&pk).unwrap();
    let want = include_bytes!("data/serde/public_key_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_raw_pair() {
    let pair = Pair {
        key: Key { type_value: 1u64, key_data: vec![0u8, 1u8, 2u8, 3u8] },
        value: vec![0u8, 1u8, 2u8, 3u8],
    };
    let got = serialize(&pair).unwrap();
    let want = include_bytes!("data/serde/raw_pair_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_proprietary_key() {
    let key = ProprietaryKey {
        prefix: vec![0u8, 1u8, 2u8, 3u8],
        subtype: 1u64,
        key: vec![0u8, 1u8, 2u8, 3u8],
    };
    let got = serialize(&key).unwrap();
    let want = include_bytes!("data/serde/proprietary_key_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_taproot_sig() {
    let s = include_str!("data/serde/taproot_sig_hex");
    let sig = taproot::Signature {
        signature: s.trim().parse::<secp256k1::schnorr::Signature>().unwrap(),
        sighash_type: TapSighashType::All,
    };

    let got = serialize(&sig).unwrap();
    let want = include_bytes!("data/serde/taproot_sig_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_taptree() {
    let ver = LeafVersion::from_consensus(0).unwrap();
    let script = ScriptBuf::from(vec![0u8, 1u8, 2u8]);
    let mut builder = TaprootBuilder::new().add_leaf_with_ver(1, script.clone(), ver).unwrap();
    builder = builder.add_leaf(1, script).unwrap();
    let tree = TapTree::try_from(builder).unwrap();

    let got = serialize(&tree).unwrap();
    let want = include_bytes!("data/serde/taptree_bincode") as &[_];
    assert_eq!(got, want)
}

// Used to get a 256 bit integer as a byte array.
fn le_bytes() -> [u8; 32] {
    let x: u128 = 0xDEAD_BEEF_CAFE_BABE_DEAD_BEEF_CAFE_BABE;
    let y: u128 = 0xCAFE_DEAD_BABE_BEEF_CAFE_DEAD_BABE_BEEF;

    let mut bytes = [0_u8; 32];

    bytes[..16].copy_from_slice(&x.to_le_bytes());
    bytes[16..].copy_from_slice(&y.to_le_bytes());

    bytes
}

#[test]
fn serde_regression_work() {
    let work = Work::from_le_bytes(le_bytes());
    let got = serialize(&work).unwrap();
    let want = include_bytes!("data/serde/u256_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_target() {
    let target = Target::from_le_bytes(le_bytes());
    let got = serialize(&target).unwrap();
    let want = include_bytes!("data/serde/u256_bincode") as &[_];
    assert_eq!(got, want)
}
