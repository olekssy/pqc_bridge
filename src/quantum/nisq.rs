// Placeholder for NISQ interface
// TODO: Implement connection to quantum random number generator

#[allow(dead_code)]
pub fn get_quantum_random_bytes(count: usize) -> Vec<u8> {
    // For now, fall back to classical PRNG
    // Later: integrate with real quantum hardware
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut bytes = vec![0u8; count];
    rng.fill_bytes(&mut bytes);
    bytes
}
