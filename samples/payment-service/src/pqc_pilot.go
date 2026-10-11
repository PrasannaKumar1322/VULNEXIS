package pilot

// Pilot: hybrid key exchange for internal gateway traffic.
// Uses X25519MLKEM768 for TLS and ML-DSA-65 for release signing.
const kex = "X25519MLKEM768"
const sig = "ML-DSA-65"
