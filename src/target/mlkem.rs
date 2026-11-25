// VÄRN-60 (Anu) — PQClean ML-KEM target (via pqcrypto-mlkem) for the FO-oracle test.

use crate::analysis::harness::time_with_work;
use pqcrypto_traits::kem::{Ciphertext as _, SharedSecret as _};
use serde::Serialize;
use std::hint::black_box;

#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
pub enum SecurityLevel {
    #[serde(rename = "ML-KEM-512")]
    MlKem512,
    #[serde(rename = "ML-KEM-768")]
    MlKem768,
    #[serde(rename = "ML-KEM-1024")]
    MlKem1024,
}

impl std::fmt::Display for SecurityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityLevel::MlKem512 => write!(f, "ML-KEM-512"),
            SecurityLevel::MlKem768 => write!(f, "ML-KEM-768"),
            SecurityLevel::MlKem1024 => write!(f, "ML-KEM-1024"),
        }
    }
}

/// One input class of the FO-oracle test: a fixed byte string of ciphertext length.
pub struct TestClass {
    pub name: String,
    pub ciphertext: Vec<u8>,
    /// `Some(secret)`: decapsulation must return this secret (accept path).
    /// `None`: decapsulation must not return the secret of the valid class
    /// (implicit rejection).
    pub expected_secret: Option<Vec<u8>>,
}

pub struct MlKemTarget {
    pub level: SecurityLevel,
    inner: TargetInner,
}

// one value per run; the size difference between the variants does not matter
#[allow(clippy::large_enum_variant)]
enum TargetInner {
    Kem512 { pk: pqcrypto_mlkem::mlkem512::PublicKey, sk: pqcrypto_mlkem::mlkem512::SecretKey },
    Kem768 { pk: pqcrypto_mlkem::mlkem768::PublicKey, sk: pqcrypto_mlkem::mlkem768::SecretKey },
    Kem1024 { pk: pqcrypto_mlkem::mlkem1024::PublicKey, sk: pqcrypto_mlkem::mlkem1024::SecretKey },
}

impl MlKemTarget {
    pub fn new(level: SecurityLevel) -> Self {
        let inner = match level {
            SecurityLevel::MlKem512 => {
                let (pk, sk) = pqcrypto_mlkem::mlkem512::keypair();
                TargetInner::Kem512 { pk, sk }
            }
            SecurityLevel::MlKem768 => {
                let (pk, sk) = pqcrypto_mlkem::mlkem768::keypair();
                TargetInner::Kem768 { pk, sk }
            }
            SecurityLevel::MlKem1024 => {
                let (pk, sk) = pqcrypto_mlkem::mlkem1024::keypair();
                TargetInner::Kem1024 { pk, sk }
            }
        };
        MlKemTarget { level, inner }
    }

    /// Honest encapsulation to this key: (ciphertext, shared secret).
    pub fn encapsulate(&self) -> (Vec<u8>, Vec<u8>) {
        match &self.inner {
            TargetInner::Kem512 { pk, .. } => {
                let (ss, ct) = pqcrypto_mlkem::mlkem512::encapsulate(pk);
                (ct.as_bytes().to_vec(), ss.as_bytes().to_vec())
            }
            TargetInner::Kem768 { pk, .. } => {
                let (ss, ct) = pqcrypto_mlkem::mlkem768::encapsulate(pk);
                (ct.as_bytes().to_vec(), ss.as_bytes().to_vec())
            }
            TargetInner::Kem1024 { pk, .. } => {
                let (ss, ct) = pqcrypto_mlkem::mlkem1024::encapsulate(pk);
                (ct.as_bytes().to_vec(), ss.as_bytes().to_vec())
            }
        }
    }

    /// Untimed decapsulation, used for the correctness check before measuring.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Vec<u8> {
        match &self.inner {
            TargetInner::Kem512 { sk, .. } => {
                let ct = pqcrypto_mlkem::mlkem512::Ciphertext::from_bytes(ciphertext).expect("ciphertext length");
                pqcrypto_mlkem::mlkem512::decapsulate(&ct, sk).as_bytes().to_vec()
            }
            TargetInner::Kem768 { sk, .. } => {
                let ct = pqcrypto_mlkem::mlkem768::Ciphertext::from_bytes(ciphertext).expect("ciphertext length");
                pqcrypto_mlkem::mlkem768::decapsulate(&ct, sk).as_bytes().to_vec()
            }
            TargetInner::Kem1024 { sk, .. } => {
                let ct = pqcrypto_mlkem::mlkem1024::Ciphertext::from_bytes(ciphertext).expect("ciphertext length");
                pqcrypto_mlkem::mlkem1024::decapsulate(&ct, sk).as_bytes().to_vec()
            }
        }
    }

    /// Timed decapsulation in ns, followed inside the timed region by `work`
    /// iterations of added work (see harness::AddedWork). The ciphertext
    /// object is built outside the timed region; the same code runs for every
    /// input class.
    pub fn timed_decapsulate(&self, ciphertext: &[u8], work: u32) -> u64 {
        match &self.inner {
            TargetInner::Kem512 { sk, .. } => {
                let ct = pqcrypto_mlkem::mlkem512::Ciphertext::from_bytes(ciphertext).expect("ciphertext length");
                time_with_work(work, || pqcrypto_mlkem::mlkem512::decapsulate(black_box(&ct), black_box(sk)))
            }
            TargetInner::Kem768 { sk, .. } => {
                let ct = pqcrypto_mlkem::mlkem768::Ciphertext::from_bytes(ciphertext).expect("ciphertext length");
                time_with_work(work, || pqcrypto_mlkem::mlkem768::decapsulate(black_box(&ct), black_box(sk)))
            }
            TargetInner::Kem1024 { sk, .. } => {
                let ct = pqcrypto_mlkem::mlkem1024::Ciphertext::from_bytes(ciphertext).expect("ciphertext length");
                time_with_work(work, || pqcrypto_mlkem::mlkem1024::decapsulate(black_box(&ct), black_box(sk)))
            }
        }
    }

    /// Input classes for the FO-oracle test. Every class is one fixed byte
    /// string of ciphertext length. ML-KEM decodes any such string; only the
    /// re-encryption check in decapsulation differs, so every class except
    /// the two honest ones takes the implicit-rejection path.
    ///
    ///   valid       — honest encapsulation to this key (reference class)
    ///   valid-2     — a second honest encapsulation to this key (accept path,
    ///                 different message and ciphertext)
    ///   other-key   — honest encapsulation to a different key
    ///   all-zero, all-ones
    ///   bit-flip-k  — the valid ciphertext with bit k flipped; eight
    ///                 positions spread evenly over the ciphertext, the last
    ///                 one in its last byte (the second ciphertext component)
    ///   random-k    — uniformly random bytes
    pub fn generate_test_classes(&self) -> Vec<TestClass> {
        let mut classes: Vec<TestClass> = Vec::new();
        let (valid_ct, valid_ss) = self.encapsulate();
        let len = valid_ct.len();

        classes.push(TestClass { name: "valid".into(), ciphertext: valid_ct.clone(), expected_secret: Some(valid_ss) });
        let (valid2_ct, valid2_ss) = self.encapsulate();
        classes.push(TestClass { name: "valid-2".into(), ciphertext: valid2_ct, expected_secret: Some(valid2_ss) });

        let other = MlKemTarget::new(self.level);
        let (other_ct, _) = other.encapsulate();
        classes.push(TestClass { name: "other-key".into(), ciphertext: other_ct, expected_secret: None });
        classes.push(TestClass { name: "all-zero".into(), ciphertext: vec![0u8; len], expected_secret: None });
        classes.push(TestClass { name: "all-ones".into(), ciphertext: vec![0xFF; len], expected_secret: None });

        const FLIPS: usize = 8;
        for k in 0..FLIPS {
            let bit = (k * (len * 8 - 8)) / (FLIPS - 1) + 3; // spread over the ciphertext
            let mut flipped = valid_ct.clone();
            flipped[bit / 8] ^= 1 << (bit % 8);
            classes.push(TestClass { name: format!("bit-flip-{}", bit), ciphertext: flipped, expected_secret: None });
        }

        for i in 0..4 {
            let random: Vec<u8> = (0..len).map(|_| rand::random()).collect();
            classes.push(TestClass { name: format!("random-{}", i), ciphertext: random, expected_secret: None });
        }

        classes
    }
}
