//! Exports graviola's public ML-KEM-768 API from a shared library.
//!
//! `scan-instrs.py` links this, so that the linker's dead-code elimination leaves only the code
//! these entry points can reach, and scans what is left. Nothing here needs to run.

use graviola::key_agreement::mlkem768::{Ciphertext, DecapKey, EncapKey};

/// Key generation, and serializing both keys.
#[unsafe(no_mangle)]
pub extern "C" fn probe_keygen(dk_out: &mut [u8; 2400], ek_out: &mut [u8; 1184]) -> bool {
    let Ok(dk) = DecapKey::generate() else {
        return false;
    };
    *ek_out = dk.encapsulation_key().as_bytes();
    *dk_out = dk.as_bytes();
    true
}

/// Parsing (and validating) an encapsulation key, then encapsulating to it.
#[unsafe(no_mangle)]
pub extern "C" fn probe_encaps(
    ek: &[u8; 1184],
    ct_out: &mut [u8; 1088],
    ss_out: &mut [u8; 32],
) -> bool {
    let Ok(ek) = EncapKey::from_bytes(ek) else {
        return false;
    };
    let Ok((ss, ct)) = ek.encaps() else {
        return false;
    };
    *ct_out = *ct.as_ref();
    *ss_out = *ss.as_ref();
    true
}

/// Decapsulation, with a freshly generated key: graviola has no way to load a decapsulation key.
#[unsafe(no_mangle)]
pub extern "C" fn probe_decaps(ct: &[u8; 1088], ss_out: &mut [u8; 32]) -> bool {
    let Ok(dk) = DecapKey::generate() else {
        return false;
    };
    *ss_out = *dk.decaps(&Ciphertext::from(*ct)).as_ref();
    true
}
