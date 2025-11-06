use base64::{prelude::BASE64_STANDARD, Engine};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
struct DilithiumKey {
    public_key: Vec<u8>,
    #[zeroize(skip)]
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

    pub fn get_public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn get_secret_key(&self) -> Result<&pqc_dilithium::Keypair, &'static str> {
        match &self.secret_key {
            None => Err("Missing secret key"),
            Some(keypair) => Ok(keypair),
        }
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct KyberKey {
    #[zeroize(skip)]
    public_key: Vec<u8>,
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

    pub fn get_public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn get_secret_key(&self) -> Result<&Vec<u8>, &'static str> {
        match &self.secret_key {
            None => Err("Missing secret key"),
            Some(secret_key) => Ok(secret_key),
        }
    }
}

/// A container for Dilithium and Kyber keys
/// Can contain public only or both public and secret keys
/// Example:
/// ```
/// use pqc_bridge::KeyPair;
///
/// let keypair = KeyPair::generate();
/// let public_keypair = keypair.to_public_key();
///
/// let message = b"Test message";
///
/// let signature = keypair.sign(message);
/// let is_valid = keypair.verify(message, &signature);
/// assert!(is_valid);
///
/// let (ciphertext, shared_secret) = keypair.encapsulate();
/// let decapsulated_secret = keypair.decapsulate(&ciphertext);
/// assert_eq!(shared_secret, decapsulated_secret);
/// ```
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
    pub fn from_public_keys(
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

    pub fn to_json(&self) -> String {
        let kyber_pk_b64 = Self::serialize(&self.kyber_key.public_key);
        let kyber_sk_b64 = match &self.kyber_key.secret_key {
            Some(sk) => Self::serialize(sk),
            None => "".to_string(),
        };
        let dilithium_pk_b64 = Self::serialize(&self.dilithium_key.public_key);

        serde_json::to_string_pretty(&serde_json::json!({
            "kyber_public_key": kyber_pk_b64,
            "kyber_secret_key": kyber_sk_b64,
            "dilithium_public_key": dilithium_pk_b64,
            "dilithium_secret_key": "", // Not serializing secret key for Dilithium
        }))
        .unwrap()
    }

    pub fn from_json(json_str: &str) -> Result<Self, serde_json::Error> {
        #[derive(serde::Deserialize)]
        struct KeyPairJson {
            kyber_public_key: String,
            kyber_secret_key: String,
            dilithium_public_key: String,
            dilithium_secret_key: String,
        }

        let kp_json: KeyPairJson = serde_json::from_str(json_str)?;

        let kyber_public = Self::deserialize(&kp_json.kyber_public_key);
        let kyber_secret = if kp_json.kyber_secret_key.is_empty() {
            None
        } else {
            Some(Self::deserialize(&kp_json.kyber_secret_key))
        };

        let dilithium_public = BASE64_STANDARD
            .decode(kp_json.dilithium_public_key)
            .unwrap();

        Ok(KeyPair {
            dilithium_key: DilithiumKey {
                public_key: dilithium_public,
                secret_key: None,
            },
            kyber_key: KyberKey {
                public_key: kyber_public,
                secret_key: kyber_secret,
            },
        })
    }

    /// serializes encryption artifact to base64 string
    fn serialize(obj: &[u8]) -> String {
        BASE64_STANDARD.encode(obj)
    }

    /// deserializes base64 string to encryption artifact
    fn deserialize(b64_str: &str) -> Vec<u8> {
        BASE64_STANDARD.decode(b64_str).unwrap()
    }

    /// Converts to public key
    /// Returns KeyPair with only public keys
    /// Use for sharing public keys without secret keys
    /// Example:
    /// ```
    /// use pqc_bridge::KeyPair;
    ///
    /// let keypair = KeyPair::generate();
    /// let public_keypair = keypair.to_public_key();
    /// ```
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
    /// Panics if secret key is missing
    /// Returns signature as byte vector
    /// Example:
    /// ```
    /// use pqc_bridge::KeyPair;
    ///
    /// let message = b"Test message";
    /// let keypair = KeyPair::generate();
    ///
    /// let signature = keypair.sign(message);
    /// ```
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let sk = self.dilithium_key.get_secret_key().ok();
        match sk {
            None => panic!("Missing secret key"),
            Some(sk) => sk.sign(message).to_vec(),
        }
    }

    /// Verifies Dilithium signature
    /// Returns true if signature is valid, false otherwise
    /// Example:
    /// ```
    /// use pqc_bridge::KeyPair;
    ///
    /// let message = b"Test message";
    /// let keypair = KeyPair::generate();
    ///
    /// let signature = keypair.sign(message);
    /// let is_valid = keypair.verify(message, &signature);
    /// assert!(is_valid);
    /// ```
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        pqc_dilithium::verify(signature, message, self.dilithium_key.get_public_key()).is_ok()
    }

    /// Encapsulates symmetric key into ciphertext and shared_secret
    /// Returns (ciphertext, shared_secret)
    /// Example:
    /// ```
    /// use pqc_bridge::KeyPair;
    ///
    /// let keypair = KeyPair::generate();
    /// let (ciphertext, shared_secret) = keypair.encapsulate();
    /// ```
    pub fn encapsulate(&self) -> (Vec<u8>, Vec<u8>) {
        let mut rng = rand::thread_rng();
        let (ciphertext, shared_secret) =
            pqc_kyber::encapsulate(self.kyber_key.get_public_key(), &mut rng).unwrap();
        (ciphertext.to_vec(), shared_secret.to_vec())
    }

    /// Decapsulates symmetric key
    /// Panics if secret key is missing
    /// Returns shared_secret
    /// Example:
    /// ```
    /// use pqc_bridge::KeyPair;
    ///
    /// let keypair = KeyPair::generate();
    /// let (ciphertext, shared_secret) = keypair.encapsulate();
    /// let decapsulated_secret = keypair.decapsulate(&ciphertext);
    /// assert_eq!(shared_secret, decapsulated_secret);
    /// ```
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Vec<u8> {
        let sk = self.kyber_key.get_secret_key().ok();
        match sk {
            None => panic!("Missing secret key"),
            Some(sk) => pqc_kyber::decapsulate(ciphertext, sk).unwrap().to_vec(),
        }
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
            assert!(!dilithium_key.get_public_key().is_empty());
            assert!(dilithium_key.get_secret_key().is_ok());
        }

        #[test]
        fn test_new_from_public_key() {
            let public_key = vec![0; 10];
            let new_key = DilithiumKey {
                public_key: public_key.clone(),
                secret_key: None,
            };
            assert_eq!(new_key.get_public_key(), &public_key);
            assert!(new_key.get_secret_key().is_err());
        }
    }

    mod test_kyber {
        use super::*;

        #[test]
        fn test_key_generation() {
            let kyber_key = KyberKey::generate();
            assert!(!kyber_key.get_public_key().is_empty());
            assert!(kyber_key.get_secret_key().is_ok());
        }

        #[test]
        fn test_key_from_public_key() {
            let public_key = vec![0; 10];
            let kyber_key = KyberKey {
                public_key: public_key.clone(),
                secret_key: None,
            };
            assert_eq!(kyber_key.get_public_key(), &public_key);
        }

        #[test]
        fn test_new_from_secret_key() {
            let public_key = vec![0; 10];
            let secret_key = vec![1; 10];
            let kyber_key = KyberKey {
                public_key: public_key.clone(),
                secret_key: Some(secret_key.clone()),
            };
            assert_eq!(kyber_key.get_public_key(), &public_key);
            assert_eq!(kyber_key.get_secret_key().unwrap(), &secret_key);
        }
    }

    mod test_keypair {
        use super::*;

        #[test]
        fn test_keypair_generation() {
            let keypair = KeyPair::generate();
            assert!(!keypair.dilithium_key.get_public_key().is_empty());
            assert!(!keypair.kyber_key.get_public_key().is_empty());
        }

        #[test]
        fn test_keypair_from_public_keys() {
            let dilithium_key = DilithiumKey::generate();
            let kyber_key = KyberKey::generate();

            let keypair = KeyPair::from_public_keys(
                Some(dilithium_key.get_public_key().to_vec()),
                Some(kyber_key.get_public_key().to_vec()),
            );

            assert_eq!(
                keypair.dilithium_key.get_public_key(),
                dilithium_key.get_public_key()
            );
            assert_eq!(
                keypair.kyber_key.get_public_key(),
                kyber_key.get_public_key()
            );
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

        #[test]
        fn test_sign_verify() {
            let keypair = KeyPair::generate();
            let message = b"Test message";
            let signature = keypair.sign(message);
            let is_valid = keypair.verify(message, &signature);
            assert!(is_valid);
        }

        #[test]
        fn test_fixed_size_signature() {
            let sig_size = 3293; // Const size of Dilithium3 signature of the SHA3-256 hash
            let keypair = KeyPair::generate();
            let message = b"Test message";
            let signature = keypair.sign(message);
            assert_eq!(signature.len(), sig_size);

            let message_alt = b"Another test message of different length";
            let signature_alt = keypair.sign(message_alt);
            assert_eq!(signature_alt.len(), sig_size);

            assert_eq!(signature.len(), signature_alt.len());
        }

        #[test]
        fn test_verify_invalid_signature() {
            let keypair = KeyPair::generate();
            let message = b"Test message";
            let invalid_signature = b"InvalidSignature";
            let is_valid = keypair.verify(message, invalid_signature);
            assert!(!is_valid);
        }

        #[test]
        #[should_panic]
        fn test_sign_without_secret_key() {
            let keypair = KeyPair::from_public_keys(
                Some(DilithiumKey::generate().get_public_key().to_vec()),
                None,
            );
            let message = b"Test message";
            keypair.sign(message);
        }

        #[test]
        fn test_key_encapsulation_decapsulation() {
            let keypair = KeyPair::generate();
            let (ciphertext, shared_secret) = keypair.encapsulate();
            assert!(!ciphertext.is_empty());
            assert_eq!(shared_secret.len(), 32); // Kyber shared secret length is 32 bytes

            let decapsulated_secret = keypair.decapsulate(&ciphertext);
            assert_eq!(shared_secret, decapsulated_secret);
        }

        #[test]
        #[should_panic]
        fn test_decapsulate_without_secret_key() {
            let keypair = KeyPair::from_public_keys(
                None,
                Some(KyberKey::generate().get_public_key().to_vec()),
            );
            let ciphertext = vec![0; 10];
            keypair.decapsulate(&ciphertext);
        }

        #[test]
        fn test_keypair_serialization() {
            let keypair = KeyPair::generate();
            let json_str = keypair.to_json();
            println!("Serialized KeyPair: {}", json_str);
            let deserialized_keypair = KeyPair::from_json(&json_str).unwrap();

            assert_eq!(
                keypair.dilithium_key.public_key,
                deserialized_keypair.dilithium_key.public_key
            );
            assert_eq!(
                keypair.kyber_key.public_key,
                deserialized_keypair.kyber_key.public_key
            );
        }
    }
}
