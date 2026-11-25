// Demonstration: decapsulation time differs from key to key through public
// data, and this has nothing to do with accepting or rejecting.
//
//   cargo run --release --example key_dependence [rounds]
//
// Decapsulation re-encrypts, and re-encryption regenerates the public matrix
// from the seed ρ in the key by rejection sampling. How many candidates are
// rejected depends on ρ, which is public. This example shows the effect for
// PQClean ML-KEM-768 and shows that it follows ρ, not the secret part of the
// key.
//
// For every pair of fresh keys A and B two hybrid keys are built: the secret
// part of A with the seed of B, and the secret part of B with the seed of A
// (ρ is bytes 2304..2336 of the 2400-byte decapsulation key: ŝ | t̂ | ρ |
// H(ek) | z). Eight classes are measured, each key with both ciphertexts:
//
//   (A, ct_A) (A, ct_B) (B, ct_B) (B, ct_A)
//   (A with ρ_B, ct_A) (A with ρ_B, ct_B) (B with ρ_A, ct_B) (B with ρ_A, ct_A)
//
// Every key is used by two classes, each seed and each ciphertext by four.
// Keys and ciphertexts are kept byte-interleaved (InterleavedInputs) and are
// copied into one fixed place before each timed call. The balance matters:
// an input that is used by more classes than another one can be measured
// faster for that reason alone (see analysis::harness).
//
// The two hybrid keys are test objects, not valid keys: FIPS 203 (section
// 7.3) lets an implementation check that the hash H(ek) stored in a
// decapsulation key matches the encapsulation key stored in it, and a hybrid
// key fails that check. The PQClean code measured here does not perform the
// check, which is what makes the experiment possible; a library that does
// would reject these keys.
//
// Expected:
//   * same key, rejected vs. accepted ciphertext: no difference;
//   * key B vs. key A: a difference for some pairs, the same for accepted and
//     rejected ciphertexts;
//   * secret part of A with the seed of B: runs like key B (compared with
//     key A it shows the difference between the keys, compared with key B
//     none; both comparisons use the ciphertext for key A);
//   * secret part of B with the seed of A: runs like key A.

use pqcrypto_mlkem::mlkem768;
use pqcrypto_traits::kem::{Ciphertext as _, SecretKey as _};
use std::hint::black_box;
use varn_60::analysis::harness::{compare, effect, measure_interleaved, time_ns, InterleavedInputs, MIN_ROUNDS};

/// position of the public seed ρ in the decapsulation key
const RHO: std::ops::Range<usize> = 2304..2336;

fn main() {
    let rounds: usize = match std::env::args().nth(1) {
        None => 20_000,
        Some(a) => match a.parse() {
            Ok(n) if n >= MIN_ROUNDS => n,
            _ => {
                eprintln!("usage: key_dependence [rounds, at least {}]", MIN_ROUNDS);
                std::process::exit(64);
            }
        },
    };
    let pairs = 8;
    println!("PQClean ML-KEM-768 (pqcrypto-mlkem), {} rounds per pair, eight classes per round", rounds);
    println!("positive Δ: the class named first is slower");
    for pair in 1..=pairs {
        let (pk_a, sk_a) = mlkem768::keypair();
        let (pk_b, sk_b) = mlkem768::keypair();
        let (_, ct_a) = mlkem768::encapsulate(&pk_a);
        let (_, ct_b) = mlkem768::encapsulate(&pk_b);
        let (a, b) = (sk_a.as_bytes().to_vec(), sk_b.as_bytes().to_vec());
        let mut a_with_rho_b = a.clone();
        a_with_rho_b[RHO].copy_from_slice(&b[RHO]);
        let mut b_with_rho_a = b.clone();
        b_with_rho_a[RHO].copy_from_slice(&a[RHO]);
        let keys = InterleavedInputs::new(&[&a, &b, &a_with_rho_b, &b_with_rho_a]);
        let cts = InterleavedInputs::new(&[ct_a.as_bytes(), ct_b.as_bytes()]);
        // (key, ciphertext) of every class
        let plan: [(usize, usize); 8] = [(0, 0), (0, 1), (1, 1), (1, 0), (2, 0), (2, 1), (3, 1), (3, 0)];

        let mut sk_bytes = vec![0u8; keys.input_len()];
        let mut ct_bytes = vec![0u8; cts.input_len()];
        let mut sk_buf = sk_a;
        let mut ct_buf = ct_a;
        let m = measure_interleaved(plan.len(), rounds, 200, |c| {
            keys.load(plan[c].0, &mut sk_bytes);
            cts.load(plan[c].1, &mut ct_bytes);
            sk_buf = mlkem768::SecretKey::from_bytes(&sk_bytes).expect("key length");
            ct_buf = mlkem768::Ciphertext::from_bytes(&ct_bytes).expect("ciphertext length");
            time_ns(|| mlkem768::decapsulate(black_box(&ct_buf), black_box(&sk_buf)))
        });
        // b vs. a: positive Δ means class b is slower
        let line = |a: usize, b: usize| {
            let c = compare(&m[a], &m[b]);
            format!("{}, z = {:+.2}", effect(&c), c.sign_z)
        };
        println!("key pair {}", pair);
        println!("  key A: rejected vs. accepted ciphertext     {}", line(0, 1));
        println!("  key B: rejected vs. accepted ciphertext     {}", line(2, 3));
        println!("  key B vs. key A, accepted ciphertexts       {}", line(0, 2));
        println!("  key B vs. key A, rejected ciphertexts       {}", line(1, 3));
        println!("  secret part of A + seed of B, vs. key A     {}   (expected: as key B vs. key A)", line(0, 4));
        println!("  secret part of A + seed of B, vs. key B     {}   (expected: no difference)", line(3, 4));
        println!("  secret part of B + seed of A, vs. key A     {}   (expected: no difference)", line(0, 7));
    }
}
