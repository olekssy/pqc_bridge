use pqc_dilithium;

pub struct DilithiumKeyPair {
    pub public_key: Vec<u8>,
    secret_key: pqc_dilithium::Keypair,
}

impl DilithiumKeyPair {
    pub fn generate() -> Self {
        let dilithium_keypair = pqc_dilithium::Keypair::generate();
        DilithiumKeyPair {
            public_key: dilithium_keypair.public.to_vec(),
            secret_key: dilithium_keypair,
        }
    }

    pub fn expose_secret(&self) -> &[u8] {
        self.secret_key.expose_secret()
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.secret_key.sign(message).to_vec()
    }

    pub fn verify(signature: &[u8], message: &[u8], public_key: &[u8]) -> bool {
        pqc_dilithium::verify(signature, message, public_key).is_ok()
    }
}
