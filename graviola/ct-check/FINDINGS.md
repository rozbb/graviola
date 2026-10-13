# Instruction-scan findings

`./ct-check.sh` as of commit `1a9dfcde`, rustc 1.98.1, 2026-10-13. The scan fails: 262
instructions in 24 (mnemonic, symbol) groups are not on Intel's DOIT list and are not
allowlisted. 74 of them handle secret data and are listed under Findings. The other 188 are false
positives that can't be allowlisted, explained in their own section.

The scan found no divides and no calls to software divide routines.

On x86-64 graviola has one ML-KEM implementation, ML-KEM-768. Its arithmetic is hand-written AVX2
assembly in `asm!` blocks, with Rust around it, so there is no serial backend to compare. The
four configs (`base`, `base-size`, `v3`, `v3-size`) change only how the Rust is compiled.

Graviola is a whole cryptography library. The probe exports only the ML-KEM-768 API from a
shared library, and the linker drops everything else, so the scan covers exactly the code ML-KEM
reaches: 24k-47k instructions depending on config. Functions that ship prebuilt with the toolchain
(std, core, compiler-builtins) and the C runtime's startup code are left out.

Source lines were found by rebuilding each config with `-C debuginfo=1` and debug info kept,
which gave the same instruction counts as the scanned builds, and asking `addr2line -i` for each
instruction. For instructions inside an `asm!` block, debug info points at the `asm!` call. The
line below is the matching instruction in the assembly text, found by searching that block.

## Findings

| # | Instruction | Config | Source | Count |
|---|---|---|---|---|
| 1 | `vmovhpd` | all | `src/low/x86_64/sha3_keccak4_f1600_alt.rs:652, 654` | 40 |
| 2 | `shufps` | base | `src/mid/mlkem768.rs:924` | 28 |
| 3 | `rep movsq` | base-size | `src/mid/sha3.rs:155-198` | 6 |

1. **4-way Keccak's last-lane store (assembly).** After de-interleaving, `A[24]` of the second
   and fourth states is stored with `vmovhpd` (the high half of an XMM register). The listed
   alternatives are `VPEXTRQ` + `MOV`, or `VPSHUFD`/`VPUNPCKHQDQ` then `VMOVQ`. It sits in
   `one_shot_sextet`, the six SHAKE256 PRF calls that expand the secret seed into the CBD
   inputs, as well as in the public matrix sampling.

2. **CBD at baseline x86-64 (Rust).** `*coeff = a - b` is vectorized with
   `shufps` to narrow lanes, since SSE2 has no integer instruction for it. This is `sample_cbd2`,
   inlined into `sample_poly_cbd_dual` and `kpke_encrypt`. It samples the secret vectors s, e, r,
   e1 and e2.

3. **PRF state copies (Rust).** In the size-optimized baseline build, the six 25-word Keccak
   states that `one_shot_sextet` builds (`let mut states = [{ ... s }, ...]`) are copied with
   `rep movsq`. The count is fixed (25), and Intel lists `REP MOVSB/W/D` as data-independent
   except in the count, but not the 64-bit form. The states hold the secret seed.

## False positives

These are on public data, or never touch data at all, but can't be allowlisted. They are inlined
into `keygen_internal`, the SHA-3 contexts and other functions that handle secrets, and an entry
covering those would hide any later finding on secret data there (`--selftest` rejects such
entries).

**`xchg rdi, r15` in the scalar Keccak** (176 instructions, all configs).
`src/low/x86_64/sha3_keccak_f1600.rs:237, 432` swap the pointer to the state with the pointer to
the scratch copy on the stack, twice per pass of the round loop. The operands are two addresses,
never state words. This is the single-lane Keccak behind SHA3-256/512 and SHAKE, so it is
everywhere.

**`pext` and `popcnt` in rejection sampling** (8 instructions, base and v3).
`src/low/x86_64/mlkem_rej_uniform_vartime.rs:100, 106` compact and count the accepted lanes when
sampling the matrix A from XOF(`rho`). `rho` is public. The same instructions in
`_sample_poly_ntt_quad` and `Shake128ForMlKem::sample`, which do nothing else, are allowlisted.
These 8 are copies inlined into `keygen_internal` and `EncapKey::from_bytes`. The routine's
name already says it is variable-time.

**`movbe` in key generation** (4 instructions, v3-size). `src/mid/mlkem768.rs:432-435` build the
byte pair `[j, i]` for each matrix entry. They come from the constant table
`SAMPLE_POLY_WORK`, and LLVM swaps their bytes as it stores them.

## Allowlisted

These are in `instr-allowlist.txt` with reasons. Listed here so the report covers every hit.

| Instructions | Where | Why |
|---|---|---|
| `cmpxchg` | `getrandom::backends::use_file::open_or_wait` | publishes the `/dev/urandom` file descriptor |
| `pext`, `popcnt` | `Coeffs<2304, Ntt>::_sample_poly_ntt_quad`, `Shake128ForMlKem::sample` | rejection sampling of XOF(`rho`), public |

`X86_EXTRA` in `scan-instrs.py` accepts these for all code:
- `vmovups`, `vmovaps` and `vxorps`, as the VEX forms of the listed `MOVUPS`, `MOVAPS` and `XORPS`.
- `endbr64`, which begins each of graviola's assembly routines and has no operands.
- `int3`, the linker's padding after functions that end in a call that never returns. It is never
  executed.

## Not covered

The probe calls the public ML-KEM-768 API: `DecapKey::generate`, `decaps`, `as_bytes` and
`encapsulation_key`, plus `EncapKey::from_bytes`, `encaps` and `as_bytes`. The `#[doc(hidden)]`
`*_internal` functions are reached through those. There is no API to load a decapsulation key, so
there is nothing to scan for one. The aarch64 implementation is not scanned.
