#![no_std]
#![cfg_attr(test, feature(test))]
#![warn(missing_docs)]

//! Implementation of the BEAR block cipher construction.
//!
//! BEAR is a variable-block-size block cipher that uses a stream cipher
//! and a cryptographic hash function to construct a wide-block cipher.
//! This specific implementation uses ChaCha20 as the stream cipher and
//! BLAKE3 as the extensible-output function (XOF) hash.

#[cfg(test)]
extern crate test;

use core::marker::PhantomData;

use blake3::Hasher;
use chacha20::ChaCha20;
use cipher::{
    Array, BlockCipherDecBackend, BlockCipherEncBackend, BlockSizeUser, InOutBuf, IvSizeUser,
    KeyIvInit, KeySizeUser, ParBlocksSizeUser, StreamCipher,
    consts::{U1, U4096},
    typenum::{IsGreater, Sum, Unsigned},
};
use hybrid_array::ArraySize;

/// The key size in bytes for the underlying ChaCha20 stream cipher (32 bytes).
type ChaCha20KeySize = <ChaCha20 as KeySizeUser>::KeySize;

/// The initialization vector (IV) size in bytes for the underlying ChaCha20 stream cipher (12 bytes).
type ChaCha20IvSize = <ChaCha20 as IvSizeUser>::IvSize;

/// The total size of the ChaCha20 key and IV combined (44 bytes).
/// This defines the size of the "header" or left part of the unbalanced Feistel network.
type ChaCha20KeyAndIvSize = Sum<ChaCha20KeySize, ChaCha20IvSize>;

/// The Bear wide-block cipher.
///
/// Bear is constructed using a 3-step unbalanced Feistel network. It splits
/// the data block of size `N` into a small left segment (the stream cipher's
/// Key + IV size) and a large right segment (the remainder of the block).
///
/// `N` must be an `ArraySize` strictly greater than the combined size of ChaCha20 key and nonce.
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct Bear<N: ArraySize>
where
    N: IsGreater<ChaCha20KeyAndIvSize>,
{
    /// Two separate BLAKE3 subkeys used for the hashing rounds.
    key: [[u8; blake3::KEY_LEN]; 2],
    _marker: PhantomData<N>,
}

impl<N: ArraySize> Bear<N>
where
    N: IsGreater<ChaCha20KeyAndIvSize>,
{
    /// Creates a new Bear block cipher instance.
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
        let (left, right) = block.into_buf().split_at(ChaCha20KeyAndIvSize::USIZE);

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
        let mut hk_xof = Hasher::new_keyed(key)
            .update(&right.get_in())
            .finalize_xof();
        let mut hk_digest = Array::<u8, ChaCha20KeyAndIvSize>::default();
        hk_xof.fill(&mut hk_digest);
        left.xor_in2out(&hk_digest);

        #[cfg(feature = "zeroize")]
        {
            use zeroize::Zeroize;
            hk_digest.zeroize();
        }
        InOutBuf::from(left.into_out())
    }

    #[inline(always)]
    fn even_round<'buf>(
        left: &InOutBuf<'buf, 'buf, u8>,
        mut right: InOutBuf<'buf, 'buf, u8>,
    ) -> InOutBuf<'buf, 'buf, u8> {
        let (key, iv) = left.get_in().split_at(ChaCha20KeySize::USIZE);
        let mut stream = ChaCha20::new_from_slices(key, iv)
            .expect("slice lengths are guaranteed by typenum bounds");
        stream.apply_keystream_inout(right.reborrow());

        InOutBuf::from(right.into_out())
    }
}

impl<N: ArraySize> BlockSizeUser for Bear<N>
where
    N: IsGreater<ChaCha20KeyAndIvSize>,
{
    type BlockSize = N;
}

impl<N: ArraySize> ParBlocksSizeUser for Bear<N>
where
    N: IsGreater<ChaCha20KeyAndIvSize>,
{
    type ParBlocksSize = U1;
}

impl<N: ArraySize> BlockCipherEncBackend for Bear<N>
where
    N: IsGreater<ChaCha20KeyAndIvSize>,
{
    fn encrypt_block(&self, block: cipher::InOut<cipher::Block<Self>>) {
        self.crypt_inner(false, block);
    }
}

impl<N: ArraySize> BlockCipherDecBackend for Bear<N>
where
    N: IsGreater<ChaCha20KeyAndIvSize>,
{
    fn decrypt_block(&self, block: cipher::InOut<cipher::Block<Self>>) {
        self.crypt_inner(true, block);
    }
}

/// A convenience type alias for a Bear cipher operating on 4096-byte blocks.
pub type Bear4096 = Bear<U4096>;

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use cipher::Array;
    use rand::{CryptoRng, SeedableRng, rngs::StdRng};

    /// Helper function to initialize a `Bear4096` instance with test keys.
    pub fn test_cipher(rng: &mut impl CryptoRng) -> Bear4096 {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Bear::new([
            blake3::derive_key("BEAR-BLAKE3-ChaCha20 2026-02-27 test key 1", &seed),
            blake3::derive_key("BEAR-BLAKE3-ChaCha20 2026-02-27 test key 2", &seed),
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

        let base_input = sample_block(&mut rng);
        let mut base_output = base_input.clone();
        cipher.encrypt_block_inplace(&mut base_output);

        let total_bits = 4096 * 8;
        let expected_flips = total_bits / 2;
        let tolerance = 500;

        let bits_to_test = [0, 1, 43 * 8, 44 * 8, 2048 * 8, 4095 * 8 + 7];

        for &bit_idx in &bits_to_test {
            let mut mutated_input = base_input.clone();
            let byte_idx = bit_idx / 8;
            let bit_in_byte = bit_idx % 8;
            mutated_input[byte_idx] ^= 1 << bit_in_byte;

            let mut mutated_output = mutated_input;
            cipher.encrypt_block_inplace(&mut mutated_output);

            let mut flipped_bits = 0;
            for (b1, b2) in base_output.iter().zip(mutated_output.iter()) {
                flipped_bits += (b1 ^ b2).count_ones() as usize;
            }

            let diff = (flipped_bits as isize - expected_flips as isize).abs();
            assert!(
                diff <= tolerance,
                "SAC failed for bit {}: flipped {} bits out of {}, diff {} exceeds tolerance {}",
                bit_idx,
                flipped_bits,
                total_bits,
                diff,
                tolerance
            );
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
