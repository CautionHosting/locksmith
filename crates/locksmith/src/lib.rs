mod openpgp;
mod models;

pub mod client;
pub mod server;

// Protocol:
//
// Client sends nonce
// Server sends attested nonce and public key
// Client sends OpenPGP signed public key and encrypted payload
