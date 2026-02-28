#![no_std]
#![cfg_attr(test, feature(test))]
#![warn(missing_docs)]

//! Implementation of the BEAR block cipher construction.
//!
//! BEAR is a variable-block-size block cipher that uses a stream cipher
//! and a cryptographic hash function to construct a wide-block cipher.
//! This specific implementation uses ChaCha12 as the stream cipher and
//! BLAKE3 as the extensible-output function (XOF) hash.

#[cfg(test)]
extern crate test;

use core::marker::PhantomData;

use blake3::Hasher;
use chacha20::ChaCha12;
use cipher::{
    Array, BlockCipherDecBackend, BlockCipherEncBackend, BlockSizeUser, InOutBuf, IvSizeUser,
    KeyIvInit, KeySizeUser, ParBlocksSizeUser, StreamCipher,
    consts::{U1, U4096},
    typenum::{IsGreater, Sum, Unsigned},
};
use hybrid_array::ArraySize;

/// The key size in bytes for the underlying ChaCha12 stream cipher (32 bytes).
type ChaCha12KeySize = <ChaCha12 as KeySizeUser>::KeySize;

/// The initialization vector (IV) size in bytes for the underlying ChaCha12 stream cipher (12 bytes).
type ChaCha12IvSize = <ChaCha12 as IvSizeUser>::IvSize;

/// The total size of the ChaCha12 key and IV combined (44 bytes).
/// This defines the size of the "header" or left part of the unbalanced Feistel network.
type ChaCha12KeyAndIvSize = Sum<ChaCha12KeySize, ChaCha12IvSize>;

/// The BEAR wide-block cipher.
///
/// BEAR is constructed using a 3-step unbalanced Feistel network. It splits
/// the data block of size `N` into a small left segment (the stream cipher's
/// Key + IV size) and a large right segment (the remainder of the block).
///
/// `N` must be an `ArraySize` strictly greater than the combined size of ChaCha12 key and nonce.
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct Bear<N: ArraySize>
where
    N: IsGreater<ChaCha12KeyAndIvSize>,
{
    /// Two separate BLAKE3 subkeys used for the hashing rounds.
    key: [[u8; blake3::KEY_LEN]; 2],
    _marker: PhantomData<N>,
}

impl<N: ArraySize> Bear<N>
where
    N: IsGreater<ChaCha12KeyAndIvSize>,
{
    /// Creates a new BEAR block cipher instance.
    ///
    /// # Arguments
    ///
    /// * `key` - An array containing two 32-byte subkeys for BLAKE3.
    pub const fn new(key: [[u8; blake3::KEY_LEN]; 2]) -> Self {
        Self {
            key,
            _marker: PhantomData,
        }
    }

    /// The core 3-step unbalanced Feistel network used for both encryption and decryption.
    ///
    /// # Arguments
    ///
    /// * `flip_keys` - A boolean indicating the direction of the operation.
    ///   `false` for encryption, `true` for decryption.
    /// * `data` - A mutable reference to the full data block of size `N`.
    #[inline(always)]
    fn crypt_inner(&self, flip_keys: bool, block: cipher::InOut<cipher::Block<Self>>) {
        let (left, right) = block.into_buf().split_at(ChaCha12KeyAndIvSize::USIZE);

        // Step 1: Hash the right part using the first key and XOR into the left part.
        let key = &self.key[flip_keys as usize];
        let left = Self::odd_round(key, left, &right);

        // Step 2: Use the updated left part as the Key and IV for the stream cipher,
        // and encrypt/decrypt the right part.
        let right = Self::even_round(&left, right);

        // Step 3: Hash the updated right part using the second key and XOR into the left part.
        let key = &self.key[1 - flip_keys as usize];
        Self::odd_round(key, left, &right);
    }

    #[inline(always)]
    fn odd_round<'buf>(
        key: &[u8; 32],
        mut left: InOutBuf<'buf, 'buf, u8>,
        right: &InOutBuf<'buf, 'buf, u8>,
    ) -> InOutBuf<'buf, 'buf, u8> {
        let mut hk_xof = Hasher::new_keyed(key).update(right.get_in()).finalize_xof();
        let mut hk_digest = Array::<u8, ChaCha12KeyAndIvSize>::default();
        hk_xof.fill(&mut hk_digest);
        left.xor_in2out(&hk_digest);

        #[cfg(feature = "zeroize")]
        {
            use zeroize::Zeroize;
            hk_xof.zeroize();
            hk_digest.zeroize();
        }
        InOutBuf::from(left.into_out())
    }

    #[inline(always)]
    fn even_round<'buf>(
        left: &InOutBuf<'buf, 'buf, u8>,
        mut right: InOutBuf<'buf, 'buf, u8>,
    ) -> InOutBuf<'buf, 'buf, u8> {
        let (key, iv) = left.get_in().split_at(ChaCha12KeySize::USIZE);
        let mut stream = ChaCha12::new_from_slices(key, iv)
            .expect("slice lengths are guaranteed by typenum bounds");
        stream.apply_keystream_inout(right.reborrow());

        InOutBuf::from(right.into_out())
    }
}

impl<N: ArraySize> BlockSizeUser for Bear<N>
where
    N: IsGreater<ChaCha12KeyAndIvSize>,
{
    type BlockSize = N;
}

impl<N: ArraySize> ParBlocksSizeUser for Bear<N>
where
    N: IsGreater<ChaCha12KeyAndIvSize>,
{
    type ParBlocksSize = U1;
}

impl<N: ArraySize> BlockCipherEncBackend for Bear<N>
where
    N: IsGreater<ChaCha12KeyAndIvSize>,
{
    fn encrypt_block(&self, block: cipher::InOut<cipher::Block<Self>>) {
        self.crypt_inner(false, block);
    }
}

impl<N: ArraySize> BlockCipherDecBackend for Bear<N>
where
    N: IsGreater<ChaCha12KeyAndIvSize>,
{
    fn decrypt_block(&self, block: cipher::InOut<cipher::Block<Self>>) {
        self.crypt_inner(true, block);
    }
}

/// A convenience type alias for a BEAR cipher operating on 4096-byte blocks.
pub type Bear4096 = Bear<U4096>;

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use cipher::Array;
    use rand::{CryptoRng, RngExt, SeedableRng, rngs::StdRng};

    /// Helper function to initialize a `Bear4096` instance with test keys.
    pub fn test_cipher(rng: &mut impl CryptoRng) -> Bear4096 {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Bear::new([
            blake3::derive_key("BEAR-BLAKE3-ChaCha12 2026-02-27 test key 1", &seed),
            blake3::derive_key("BEAR-BLAKE3-ChaCha12 2026-02-27 test key 2", &seed),
        ])
    }

    /// Helper function to generate a 4096-byte sample block.
    pub fn sample_block(rng: &mut impl CryptoRng) -> Array<u8, U4096> {
        let mut block = Array::default();
        rng.fill_bytes(&mut block);
        block
    }

    #[test]
    fn encrypt_is_deterministic() {
        let mut rng = StdRng::seed_from_u64(37);

        let cipher = test_cipher(&mut rng);

        let mut b1 = sample_block(&mut rng);
        let mut b2 = b1;

        cipher.encrypt_block_inplace(&mut b1);
        cipher.encrypt_block_inplace(&mut b2);

        assert_eq!(b1, b2);
    }

    #[test]
    fn different_inputs_produce_different_outputs() {
        let mut rng = StdRng::seed_from_u64(37);

        let cipher = test_cipher(&mut rng);

        let mut b1 = sample_block(&mut rng);
        let mut b2 = b1;
        b2[0] ^= 1;

        cipher.encrypt_block_inplace(&mut b1);
        cipher.encrypt_block_inplace(&mut b2);

        assert_ne!(b1, b2);
    }

    #[test]
    fn in_place_vs_cloned_encrypt_match() {
        let mut rng = StdRng::seed_from_u64(37);

        let cipher = test_cipher(&mut rng);

        let mut block1 = sample_block(&mut rng);
        let mut block2 = block1.clone();

        cipher.encrypt_block_inplace(&mut block1);
        cipher.encrypt_block_inplace(&mut block2);

        assert_eq!(block1, block2);
    }

    #[test]
    fn round_trip() {
        let mut rng = StdRng::seed_from_u64(37);

        let cipher = test_cipher(&mut rng);

        let mut block = sample_block(&mut rng);
        let original = block.clone();

        cipher.encrypt_block_inplace(&mut block);
        cipher.decrypt_block_inplace(&mut block);

        assert_eq!(block, original);
    }

    #[test]
    fn strict_avalanche_criterion() {
        let mut rng = StdRng::seed_from_u64(37);
        let cipher = test_cipher(&mut rng);

        const TOTAL_BYTES: usize = 4096;
        const TOTAL_BITS: usize = TOTAL_BYTES * 8;
        const NUM_BITS_TO_TEST: usize = 6;
        const NUM_SAMPLES: usize = 100;
        const EXPECTED_FLIPS: i32 = (NUM_SAMPLES / 2) as i32;

        let mut bits_to_test = [0; NUM_BITS_TO_TEST];
        bits_to_test.fill_with(|| rng.random_range(0..TOTAL_BITS));

        // 1. Calculate the number of independent checks we are making
        let num_independent_tests = bits_to_test.len() * TOTAL_BITS;

        // 2. We want the ENTIRE test to pass 90% of the time.
        let target_overall_success: f64 = 0.90;

        // Probability that a single bit test passes, to achieve the overall target
        let p_one_pass = target_overall_success.powf(1.0 / num_independent_tests as f64);

        // Calculate the Z-score using an approximation of the Inverse Normal CDF
        let z_score = {
            let alpha = 1.0 - p_one_pass;
            let t = (-2.0 * (alpha / 2.0).ln()).sqrt();
            let c0 = 2.515517;
            let c1 = 0.802853;
            let c2 = 0.010328;
            let d1 = 1.432788;
            let d2 = 0.189269;
            let d3 = 0.001308;
            t - (c0 + c1 * t + c2 * t * t) / (1.0 + d1 * t + d2 * t * t + d3 * t * t * t)
        };

        // 3. Calculate ideal standard error for the binomial distribution (p=0.5)
        // Standard Error (SE) of the sum = sqrt(N * p * (1-p)) = sqrt(N * 0.25)
        let standard_error = (NUM_SAMPLES as f64 * 0.25).sqrt();

        // 4. Final dynamic tolerance
        let tolerance = (z_score * standard_error).round() as isize;

        for &bit_idx in &bits_to_test {
            let mut output_bit_flips = [0; TOTAL_BITS];

            for _ in 0..NUM_SAMPLES {
                let base_input = sample_block(&mut rng);
                let mut base_output = base_input.clone();
                cipher.encrypt_block_inplace(&mut base_output);

                let mut mutated_input = base_input;
                let byte_idx = bit_idx / 8;
                let bit_in_byte = bit_idx % 8;
                mutated_input[byte_idx] ^= 1 << bit_in_byte;

                let mut mutated_output = mutated_input;
                cipher.encrypt_block_inplace(&mut mutated_output);

                for byte_i in 0..TOTAL_BYTES {
                    let diff_byte = base_output[byte_i] ^ mutated_output[byte_i];
                    if diff_byte != 0 {
                        for bit_i in 0..8 {
                            if (diff_byte >> bit_i) & 1 == 1 {
                                output_bit_flips[byte_i * 8 + bit_i] += 1;
                            }
                        }
                    }
                }
            }

            for (out_bit_idx, &flips) in output_bit_flips.iter().enumerate() {
                let diff = (flips as isize - EXPECTED_FLIPS as isize).abs();
                assert!(
                    diff <= tolerance,
                    "SAC failed for input bit {} -> output bit {}: flipped {} times out of {} samples (diff {}, max allowed {})",
                    bit_idx,
                    out_bit_idx,
                    flips,
                    NUM_SAMPLES,
                    diff,
                    tolerance
                );
            }
        }
    }
}

#[cfg(test)]
mod benches {
    use cipher::{BlockCipherDecBackend, BlockCipherEncBackend};
    use rand::{SeedableRng, rngs::StdRng};
    use test::Bencher;

    use crate::tests::{sample_block, test_cipher};

    #[bench]
    fn encrypt_4096(b: &mut Bencher) {
        let mut rng = StdRng::seed_from_u64(37);

        let cipher = test_cipher(&mut rng);
        let mut block = sample_block(&mut rng);

        b.iter(|| {
            cipher.encrypt_block_inplace(&mut block);
            test::black_box(&block);
        });
    }

    #[bench]
    fn decrypt_4096(b: &mut Bencher) {
        let mut rng = StdRng::seed_from_u64(37);

        let cipher = test_cipher(&mut rng);
        let mut block = sample_block(&mut rng);

        cipher.encrypt_block_inplace(&mut block);

        b.iter(|| {
            cipher.decrypt_block_inplace(&mut block);
            test::black_box(&block);
        });
    }
}
