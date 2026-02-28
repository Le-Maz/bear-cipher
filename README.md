# BEAR Block Cipher

A `no_std` compatible Rust implementation of the BEAR block cipher construction.

## Overview

BEAR is a provably secure block cipher that uses a large, variable block size. It was designed by Ross Anderson and Eli Biham to construct a block cipher from a stream cipher and a hash function. The cipher's design allows arbitrary sized blocks to be enciphered in three passes. The security of the cipher relies on the underlying components: an attack that finds the key would yield an attack on the hash function, the stream cipher, or both.

## Cryptographic Construction

BEAR operates as a 3-step unbalanced Feistel network. The construction utilizes two hashes and one stream cipher.

* The plaintext is split into two parts: a left segment L and a right segment R.
* The key consists of two independent subkeys, K1 and K2.

Encryption:

1. L = L ⊕ H_K1(R)
2. R = R ⊕ S(L)
3. L = L ⊕ H_K2(R)

Decryption:

1. L = L ⊕ H_K2(R)
2. R = R ⊕ S(L)
3. L = L ⊕ H_K1(R)

## Implementation Details

While the original paper conceptually uses SHA1 and SEAL, this Rust implementation specifically pairs **ChaCha12** (as the stream cipher) and **BLAKE3** (as the hash).

* **Keyed Hash Construction:** The original paper suggests a keyed hash $H_K(M)$ constructed by prepending/appending the key to the message (e.g., $H(K|M|K)$). This implementation instead utilizes **BLAKE3 in keyed mode**, which uses a specialized internal construction for keyed hashing rather than simple concatenation.
* **Subkey Sizes:** The paper specifies that subkeys $K_1$ and $K_2$ should be of length greater than the hash output size $k$. In this implementation, both subkeys are fixed at **32 bytes** (256 bits), which is the standard key length for BLAKE3, whereas the hash output used for the Feistel branch is 44 bytes to match the ChaCha12 requirements.
* **Motivation for ChaCha12:** The choice to use 12 rounds rather than standard 20 (ChaCha20) is based on optimizing performance while maintaining a consistent security margin (Aumasson, 2019).

## Usage

Add the library to your project and initialize it using two 32-byte BLAKE3 subkeys.

```rust
use cipher::{BlockCipherEncBackend, BlockCipherDecBackend, BlockSizeUser};
use cipher::Array;
use bear_cipher::{Bear, Bear4096}; 
use cipher::consts::U4096;

fn main() {
    // Subkeys are 32 bytes each
    let key1 = blake3::derive_key("Application Key Context 1", b"secret_seed_data");
    let key2 = blake3::derive_key("Application Key Context 2", b"secret_seed_data");

    let cipher = Bear4096::new([key1, key2]);

    let mut block = Array::<u8, U4096>::default();
    
    cipher.encrypt_block_inplace(&mut block);

    cipher.decrypt_block_inplace(&mut block);
}
```

## References

* Anderson, Ross J. and Biham, Eli *Two Practical and Provably Secure Block Ciphers: BEAR and LION*.
* Aumasson, Jean-Philippe *Too Much Crypto*. [Cryptology ePrint Archive, Paper 2019/1492](<https://eprint.iacr.org/2019/1492>).
