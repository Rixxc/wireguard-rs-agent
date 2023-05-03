/* Implementation of the:
 *
 * Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s
 *
 * Protocol pattern, see: http://www.noiseprotocol.org/noise.html.
 * For documentation.
 */

pub(crate) mod device;
pub(crate) mod macs;
pub(crate) mod messages;
pub(crate) mod noise;
pub(crate) mod peer;
pub(crate) mod ratelimiter;
pub(crate) mod timestamp;
pub(crate) mod types;

#[cfg(test)]
mod tests;

// publicly exposed interface

pub use device::Device;
pub use messages::{MAX_HANDSHAKE_MSG_SIZE, TYPE_COOKIE_REPLY, TYPE_INITIATION, TYPE_RESPONSE};
