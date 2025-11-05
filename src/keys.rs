use pqc_dilithium;
use pqc_kyber;
use rand;

struct DilithiumKey {
    pub public_key: Vec<u8>,
    secret_key: Option<pqc_dilithium::Keypair>,
}

impl DilithiumKey {
    pub fn generate() -> Self {
        let dilithium_keypair = pqc_dilithium::Keypair::generate();
        DilithiumKey {
            public_key: dilithium_keypair.public.to_vec(),
            secret_key: Some(dilithium_keypair),
        }
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        match &self.secret_key {
            None => panic!("Missing secret key"),
            Some(_) => self.secret_key.as_ref().unwrap().sign(message).to_vec(),
        }
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        pqc_dilithium::verify(signature, message, &self.public_key).is_ok()
    }
}

struct KyberKey {
    pub public_key: Vec<u8>,
    secret_key: Option<Vec<u8>>,
}

impl KyberKey {
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let keypair = pqc_kyber::keypair(&mut rng).unwrap();
        KyberKey {
            public_key: keypair.public.to_vec(),
            secret_key: Some(keypair.secret.to_vec()),
        }
    }

    /// Encapsulates symmetric key
    pub fn encapsulate(&self) -> (Vec<u8>, Vec<u8>) {
        let mut rng = rand::thread_rng();
        let (ciphertext, shared_secret) =
            pqc_kyber::encapsulate(&self.public_key, &mut rng).unwrap();
        (ciphertext.to_vec(), shared_secret.to_vec())
    }

    /// Decapsulates symmetric key
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Vec<u8> {
        match &self.secret_key {
            None => panic!("Missing secret key"),
            Some(secret_key) => pqc_kyber::decapsulate(ciphertext, secret_key)
                .unwrap()
                .to_vec(),
        }
    }
}

/// A container for Dilithium and Kyber keys
pub struct KeyPair {
    dilithium_key: DilithiumKey,
    kyber_key: KyberKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        KeyPair {
            dilithium_key: DilithiumKey::generate(),
            kyber_key: KyberKey::generate(),
        }
    }

    /// Creates new KeyPair from public keys:
    /// * Dilithium for signing/verification
    /// * Kyber for encryption/decryption
    ///   At least one public key must be provided.
    pub fn new_from_public_keys(
        dilithium_public: Option<Vec<u8>>,
        kyber_public: Option<Vec<u8>>,
    ) -> Self {
        if dilithium_public.is_none() && kyber_public.is_none() {
            panic!("At least one public key must be provided");
        }

        KeyPair {
            dilithium_key: DilithiumKey {
                public_key: dilithium_public.clone().unwrap(),
                secret_key: None,
            },
            kyber_key: KyberKey {
                public_key: kyber_public.clone().unwrap(),
                secret_key: None,
            },
        }
    }

    /// Converts to public key
    /// Returns KeyPair with only public keys
    /// Use for sharing public keys without secret keys
    pub fn to_public_key(&self) -> Self {
        KeyPair {
            dilithium_key: DilithiumKey {
                public_key: self.dilithium_key.public_key.clone(),
                secret_key: None,
            },
            kyber_key: KyberKey {
                public_key: self.kyber_key.public_key.clone(),
                secret_key: None,
            },
        }
    }

    /// Signs message with Dilithium
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.dilithium_key.sign(message)
    }

    /// Verifies Dilithium signature
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        self.dilithium_key.verify(message, signature)
    }

    /// Encapsulates symmetric key into ciphertext and shared_secret
    pub fn encapsulate(&self) -> (Vec<u8>, Vec<u8>) {
        self.kyber_key.encapsulate()
    }

    /// Decapsulates symmetric key from ciphertext
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Vec<u8> {
        self.kyber_key.decapsulate(ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod test_dilithium {
        use super::*;

        #[test]
        fn test_key_generation() {
            let dilithium_key = DilithiumKey::generate();
            assert!(!dilithium_key.public_key.is_empty());
        }

        #[test]
        fn test_new_from_public_key() {
            let public_key = vec![0; 10];
            let new_key = DilithiumKey {
                public_key: public_key.clone(),
                secret_key: None,
            };
            assert_eq!(new_key.public_key, public_key);
        }

        #[test]
        fn test_sign_verify() {
            let dilithium_key = DilithiumKey::generate();
            let message = b"Test message";
            let signature = dilithium_key.sign(message);
            let is_valid = dilithium_key.verify(message, &signature);
            assert!(is_valid);
        }

        #[test]
        fn test_verify_invalid_signature() {
            let dilithium_key = DilithiumKey::generate();
            let message = b"Test message";
            let invalid_signature = b"InvalidSignature";
            let is_valid = dilithium_key.verify(message, invalid_signature);
            assert!(!is_valid);
        }

        #[test]
        #[should_panic(expected = "Missing secret key")]
        fn test_sign_without_secret_key() {
            let dilithium_key = DilithiumKey {
                public_key: vec![0; 10],
                secret_key: None,
            };
            let message = b"Test message";
            dilithium_key.sign(message);
            panic!("Signing should not succeed without a secret key");
        }
    }

    mod test_kyber {
        use super::*;

        #[test]
        fn test_key_generation() {
            let kyber_key = KyberKey::generate();
            assert!(!kyber_key.public_key.is_empty());
        }

        #[test]
        fn test_key_from_public_key() {
            let public_key = vec![0; 10];
            let kyber_key = KyberKey {
                public_key: public_key.clone(),
                secret_key: None,
            };
            assert_eq!(kyber_key.public_key, public_key);
        }

        #[test]
        fn test_key_encapsulation_decapsulation() {
            let kyber_key = KyberKey::generate();
            let (ciphertext, shared_secret) = kyber_key.encapsulate();
            assert!(!ciphertext.is_empty());
            assert_eq!(shared_secret.len(), 32); // Kyber shared secret length is 32 bytes

            let decapsulated_secret = kyber_key.decapsulate(&ciphertext);
            assert_eq!(shared_secret, decapsulated_secret);
        }
    }

    mod test_keychain {
        use super::*;

        #[test]
        fn test_keypair_generation() {
            let keypair = KeyPair::generate();
            assert!(!keypair.dilithium_key.public_key.is_empty());
            assert!(!keypair.kyber_key.public_key.is_empty());
        }

        #[test]
        fn test_keypair_from_public_keys() {
            let dilithium_key = DilithiumKey::generate();
            let kyber_key = KyberKey::generate();

            let keypair = KeyPair::new_from_public_keys(
                Some(dilithium_key.public_key.clone()),
                Some(kyber_key.public_key.clone()),
            );

            assert_eq!(keypair.dilithium_key.public_key, dilithium_key.public_key);
            assert_eq!(keypair.kyber_key.public_key, kyber_key.public_key);
        }

        #[test]
        fn test_keypair_to_public_key() {
            let keypair = KeyPair::generate();
            let public_keypair = keypair.to_public_key();

            assert_eq!(
                keypair.dilithium_key.public_key,
                public_keypair.dilithium_key.public_key
            );
            assert_eq!(
                keypair.kyber_key.public_key,
                public_keypair.kyber_key.public_key
            );
        }
    }
}
