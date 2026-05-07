// Substrate standard crypt crate functions
#![allow(missing_docs)]
use crate::crypto::{
    CryptoType, CryptoTypeId, DeriveError, DeriveJunction, Pair as TraitPair,
    PublicBytes, SignatureBytes, SecretStringError,
};

use alloc::vec::Vec;
use codec::Encode;

// Falcon crate from falcon-rs 0.2.4
use falcon::safe_api::{FnDsaKeyPair, FalconSignature};
use falcon::prelude::DomainSeparation;

pub const PUBLIC_KEY_LEN: usize = 897;   // This is lengh/size of Public key in Falcon512
pub const SIGNATURE_LEN: usize = 809;    
// The standard typical signature size of Falcon512 is 666. But falcon-rs crate generate 809 bytes of signature
pub const SEED_LEN: usize = 32;

pub const CRYPTO_ID: CryptoTypeId = CryptoTypeId(*b"f512");  //This is 4 Byte crypto ID for newly added Falcon512 DSA

#[doc(hidden)]
pub struct FalconPublicTag;
#[doc(hidden)]
pub struct FalconSignatureTag;

// Tags for Public Key and Signature to distinguish between any random bytes or other DSA keys
pub type Public = PublicBytes<PUBLIC_KEY_LEN, FalconPublicTag>;
pub type Signature = SignatureBytes<SIGNATURE_LEN, FalconSignatureTag>;
type Seed = [u8; SEED_LEN];


// Hard derivation
fn derive_hard_junction(seed: &Seed, cc: &[u8; 32]) -> Seed {
    ("FalconHDKD", seed, cc)
        .using_encoded(sp_crypto_hashing::blake2_256)
}

// Pair Struct
pub struct Pair {
    inner: FnDsaKeyPair,
    seed: Seed,
}

// Clone to regenerate from seed 
impl Clone for Pair {
    fn clone(&self) -> Self {
        Pair::from_seed(&self.seed)
    }
}

//Implementation of Traits
impl TraitPair for Pair {
    type Public = Public;
    type Seed = Seed;
    type Signature = Signature;
    type ProofOfPossession = Signature;

    fn from_seed_slice(seed: &[u8]) -> Result<Self, SecretStringError> {
        if seed.len() != SEED_LEN {
            return Err(SecretStringError::InvalidSeedLength);
        }

        let mut s = [0u8; SEED_LEN];
        s.copy_from_slice(seed);

        let kp = FnDsaKeyPair::generate_deterministic(&s, 9)
            .map_err(|_| SecretStringError::InvalidSeedLength)?;

        Ok(Self {
            inner: kp,
            seed: s,
        })
    }

    fn derive<Iter: Iterator<Item = DeriveJunction>>(
        &self,
        path: Iter,
        _seed: Option<Seed>,
    ) -> Result<(Self, Option<Seed>), DeriveError> {
        let mut acc = self.seed;

        for j in path {
            match j {
                DeriveJunction::Soft(_) => return Err(DeriveError::SoftKeyInPath),
                DeriveJunction::Hard(cc) => {
                    acc = derive_hard_junction(&acc, &cc);
                }
            }
        }

        Ok((Self::from_seed(&acc), Some(acc)))
    }

    fn public(&self) -> Public {
        let pk_bytes = self.inner.public_key(); // &[u8]
    	let mut arr = [0u8; PUBLIC_KEY_LEN];
    	arr.copy_from_slice(pk_bytes);
    	Public::from_raw(arr)
    }

    #[cfg(feature = "full_crypto")]
    fn sign(&self, message: &[u8]) -> Signature {
    	let sig = self
        	.inner
        	.sign(message, &DomainSeparation::None)
        	.expect("sign failed");

    	let sig_bytes = sig.to_bytes(); 

    	let mut arr = [0u8; SIGNATURE_LEN];
    	arr.copy_from_slice(sig_bytes);

    	Signature::from_raw(arr)
    }


    fn verify<M: AsRef<[u8]>>(sig: &Signature, message: M, pubkey: &Public) -> bool {
        FalconSignature::verify(
            sig.as_ref(),
            pubkey.as_ref(),
            message.as_ref(),
            &DomainSeparation::None,
        )
        .is_ok()
    }

    fn to_raw_vec(&self) -> Vec<u8> {
        self.seed.to_vec()
    }
}

// Adjustment to make Falcon similar to other DSA
impl CryptoType for Public {
    type Pair = Pair;
}

impl CryptoType for Signature {
    type Pair = Pair;
}

impl CryptoType for Pair {
    type Pair = Pair;
}


// Tests to check the correctness of Falcon DSA 
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Pair as TraitPair;

    fn bytes(sig: &Signature) -> &[u8] {
        sig.as_ref()
    }

    fn pub_bytes(pk: &Public) -> &[u8] {
        pk.as_ref()
    }

    #[test]
    // This test will check if we can sign and verify correctly
    fn seed_pair_should_sign_and_verify512() {
        let seed: Seed = *b"12345678901234567890123456789012";  
        // In falcon-rs, deteministic keypair generation require 48 bytes seed but we are providing 32 bytes to make this similar to other DSA algorithms.  

        let pair = Pair::from_seed(&seed);
        let public = pair.public();

        let msg = b"This is a test messgae for falcon";

        let sig = pair.sign(msg);

        assert!(Pair::verify(&sig, msg.as_slice(), &public));

        assert_eq!(bytes(&sig).len(), SIGNATURE_LEN);
        assert_eq!(pub_bytes(&public).len(), PUBLIC_KEY_LEN);
    }

    #[test]
    // This test will check if we get same keypair for same seed. Deterministic keypair generation
    fn deterministic_keypair_should_match512() {
        let seed: Seed = *b"12345678901234567890123456789012";

        let p1 = Pair::from_seed(&seed);
        let p2 = Pair::from_seed(&seed);

        assert_eq!(pub_bytes(&p1.public()), pub_bytes(&p2.public()));
    }

    #[test]
    //Same seed will result in same seed but different signature, so this test will verify this
    fn signatures_should_not_be_equal512() {
        let seed: Seed = *b"12345678901234567890123456789012";

        let pair = Pair::from_seed(&seed);

        let s1 = pair.sign(b"msg1");
        let s2 = pair.sign(b"msg2");

        assert_ne!(bytes(&s1), bytes(&s2));
    }

    #[test]
    //This test to verify that we are getting same size of signature everytime. If signature size is fixed or not. It should be fixed
    fn signature_length_is_constant512() {
        let seed: Seed = *b"12345678901234567890123456789012";
        let pair = Pair::from_seed(&seed);

        let sig = pair.sign(b"hello");

        assert_eq!(bytes(&sig).len(), SIGNATURE_LEN);
    }

    #[test]
    //This test will check if size pf public key is same everytime
    fn public_key_length_is_constant512() {
        let seed: Seed = *b"12345678901234567890123456789012";
        let pair = Pair::from_seed(&seed);

        let pk = pair.public();

        assert_eq!(pub_bytes(&pk).len(), PUBLIC_KEY_LEN);
    }
}
    
  
