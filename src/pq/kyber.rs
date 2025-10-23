use pqc_kyber;
use rand;

pub struct KyberKeyPair {
    pub public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

impl KyberKeyPair {
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let keypair = pqc_kyber::keypair(&mut rng).unwrap();
        KyberKeyPair {
            public_key: keypair.public.to_vec(),
            secret_key: keypair.secret.to_vec(),
        }
    }

    pub fn expose_secret(&self) -> &[u8] {
        &self.secret_key
    }

    pub fn encapsulate(public_key: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut rng = rand::thread_rng();
        let (ciphertext, shared_secret) = pqc_kyber::encapsulate(public_key, &mut rng).unwrap();
        (ciphertext.to_vec(), shared_secret.to_vec())
    }

    pub fn decapsulate(ciphertext: &[u8], secret_key: &[u8]) -> Vec<u8> {
        pqc_kyber::decapsulate(ciphertext, secret_key)
            .unwrap()
            .to_vec()
    }
}
