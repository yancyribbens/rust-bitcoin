#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use libfuzzer_sys::fuzz_target;

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: (&[u8], &[u8])) {
    let (bytes_a, bytes_b) = data;

    let Ok(psbt_a) = bitcoin::psbt::Psbt::deserialize(bytes_a) else {
        return;
    };

    let ser = bitcoin::psbt::Psbt::serialize(&psbt_a);
    let deser = bitcoin::psbt::Psbt::deserialize(&ser).unwrap();
    assert_eq!(ser, bitcoin::psbt::Psbt::serialize(&deser));

    let Ok(mut psbt_b) = bitcoin::psbt::Psbt::deserialize(bytes_b) else {
        return;
    };

    let mut psbt_a_clone = psbt_a.clone();
    assert_eq!(psbt_b.combine(psbt_a).is_ok(), psbt_a_clone.combine(psbt_b).is_ok());
}

fuzz_target!(|data: (&[u8], &[u8])| {
    do_test(data);
});
