**2.0.1**
---------

* Style fixes

**2.0.0**
---------

* Shapeless dependency removed
* Using tagged types instead of *Array[Byte]*, *suppertagged* microframework is used for that 
* BouncyCastle 1.58

**1.3.3**
---------

* *version* method signature change in *VersionedAVLStorage*
* *rollbackVersions* method in *VersionedAVLStorage*

**1.3.2**
---------

* *prover()* in *PersistentBatchAVLProver* (don't store the ref, it is mutable!)
* No constructor for PersistentBatchAVLProver anymore, use PersistentBatchAVLProver.create

**1.3.1**
---------

* Added hash functions Whirlpool, Skein and Stribog from BouncyCastle

**1.3.0**
---------

* *performOneOperation()* return value type fix in PersistentBatchAVLProver 
* Instead of imported Java implementations for hash functions, BouncyCastle to be used for hash functions
* Because of previous item, most of hash functions were removed. Scrypto has SHA-256, Blake2b-(256/512) 
  and Keccak-(256/512) wrappers only in this version.

**1.2.3**
---------

* Index checking in Merkle proof generation
* *PersistentBatchAVLProver* interface improvements

**1.2.2**
---------

* MerkleTree and MerkleProof implementation - static Merkle trees


**1.2.1**
---------

* BatchAVLVerifier now has an interface for traversal through its tree, extractNodes() and extractFirstNode() functions
* Parameter valueLength is now optional
* Better interface for authenticated dynamic dictionaries, namely Operation/Lookup/Modification families

**1.2.0**
---------

* Versioned deterministic Merkle trees with in-memory or on-disk storage
* Authenticated skiplists
* Authenticated AVL trees
* Commutative hash
* It is possible to get results of hash and signing functions wrapped in statically sized byte array using Sized from Shapeless
