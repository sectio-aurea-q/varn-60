use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
pub enum SecurityLevel {
    MlKem512,
    MlKem768,
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

pub struct MlKemTarget {
    pub level: SecurityLevel,
    inner: TargetInner,
}

enum TargetInner {
    Kem512 {
        pk: pqcrypto_kyber::kyber512::PublicKey,
        sk: pqcrypto_kyber::kyber512::SecretKey,
    },
    Kem768 {
        pk: pqcrypto_kyber::kyber768::PublicKey,
        sk: pqcrypto_kyber::kyber768::SecretKey,
    },
    Kem1024 {
        pk: pqcrypto_kyber::kyber1024::PublicKey,
        sk: pqcrypto_kyber::kyber1024::SecretKey,
    },
}

impl MlKemTarget {
    pub fn new(level: SecurityLevel) -> Self {
        let inner = match level {
            SecurityLevel::MlKem512 => {
                let (pk, sk) = pqcrypto_kyber::kyber512::keypair();
                TargetInner::Kem512 { pk, sk }
            }
            SecurityLevel::MlKem768 => {
                let (pk, sk) = pqcrypto_kyber::kyber768::keypair();
                TargetInner::Kem768 { pk, sk }
            }
            SecurityLevel::MlKem1024 => {
                let (pk, sk) = pqcrypto_kyber::kyber1024::keypair();
                TargetInner::Kem1024 { pk, sk }
            }
        };
        MlKemTarget { level, inner }
    }

    pub fn encapsulate(&self) -> (Vec<u8>, Vec<u8>) {
        match &self.inner {
            TargetInner::Kem512 { pk, .. } => {
                let (ss, ct) = pqcrypto_kyber::kyber512::encapsulate(pk);
                (ct.as_bytes().to_vec(), ss.as_bytes().to_vec())
            }
            TargetInner::Kem768 { pk, .. } => {
                let (ss, ct) = pqcrypto_kyber::kyber768::encapsulate(pk);
                (ct.as_bytes().to_vec(), ss.as_bytes().to_vec())
            }
            TargetInner::Kem1024 { pk, .. } => {
                let (ss, ct) = pqcrypto_kyber::kyber1024::encapsulate(pk);
                (ct.as_bytes().to_vec(), ss.as_bytes().to_vec())
            }
        }
    }

    pub fn timed_decapsulate(&self, ciphertext: &[u8]) -> (Vec<u8>, u64) {
        use crate::platform::Timer;

        match &self.inner {
            TargetInner::Kem512 { sk, .. } => {
                let ct = pqcrypto_kyber::kyber512::Ciphertext::from_bytes(ciphertext)
                    .expect("invalid ciphertext length");
                let (ss, elapsed) = Timer::measure(|| {
                    pqcrypto_kyber::kyber512::decapsulate(&ct, sk)
                });
                (ss.as_bytes().to_vec(), elapsed)
            }
            TargetInner::Kem768 { sk, .. } => {
                let ct = pqcrypto_kyber::kyber768::Ciphertext::from_bytes(ciphertext)
                    .expect("invalid ciphertext length");
                let (ss, elapsed) = Timer::measure(|| {
                    pqcrypto_kyber::kyber768::decapsulate(&ct, sk)
                });
                (ss.as_bytes().to_vec(), elapsed)
            }
            TargetInner::Kem1024 { sk, .. } => {
                let ct = pqcrypto_kyber::kyber1024::Ciphertext::from_bytes(ciphertext)
                    .expect("invalid ciphertext length");
                let (ss, elapsed) = Timer::measure(|| {
                    pqcrypto_kyber::kyber1024::decapsulate(&ct, sk)
                });
                (ss.as_bytes().to_vec(), elapsed)
            }
        }
    }

    pub fn generate_attack_ciphertexts(&self, count: usize) -> Vec<(Vec<u8>, String)> {
        let mut variants: Vec<(Vec<u8>, String)> = Vec::new();
        let (valid_ct, _) = self.encapsulate();

        variants.push((valid_ct.clone(), "valid".into()));
        variants.push((vec![0u8; valid_ct.len()], "all-zero".into()));
        variants.push((vec![0xFF; valid_ct.len()], "all-ones".into()));

        for bit_pos in 0..std::cmp::min(count, 8) {
            let mut flipped = valid_ct.clone();
            flipped[bit_pos / 8] ^= 1 << (bit_pos % 8);
            variants.push((flipped, format!("bit-flip-{}", bit_pos)));
        }

        for i in 0..std::cmp::min(count, 4) {
            let mut rct = vec![0u8; valid_ct.len()];
            for b in rct.iter_mut() {
                *b = rand::random();
            }
            variants.push((rct, format!("random-{}", i)));
        }

        variants
    }

    pub fn ciphertext_size(&self) -> usize {
        match self.level {
            SecurityLevel::MlKem512 => 768,
            SecurityLevel::MlKem768 => 1088,
            SecurityLevel::MlKem1024 => 1568,
        }
    }
}
