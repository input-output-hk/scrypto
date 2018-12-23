**2.1.6**
---------

* Manifest deserialization now checks that valueLength is not negative


**2.1.5**
---------

* Fix for "BatchAVLProverManifest changes its properties after serialization/deserialization" bug 
(#58)


**2.1.4**
---------

* Minor update with dependencies update (Guava 21.x, scorex.utils 0.1.1)

**2.1.3**
---------

* Always explicit encoding in .getBytes String method
* Base* and logging are moved to scorex-utils

**2.1.2**
---------

* Base58: empty string allowed as parameter
* Reworked Base16 implementation has much better performance
* Minor changes in MerkleTree implementation 
 

**2.1.1**
---------

* Bugfix release: a bug in double rotation processing in AVL+ tree implementation has been fixed


**2.1.0**
---------

* AVL+ tree serialization, see *BatchAVLProverSerializer* class
* Possibility to get list of removed nodes, see *removedNodes()* in *BatchAVLProver* 
* Better Base58 performance
* Initial implementation of sparse Merkle trees


**2.0.5**
---------
* *randomWalk()* in *BatchAVLProver* can accept external randomness via an optional parameter

**2.0.4**
---------
* improved performance of Base58-related operations


**2.0.3**
---------
* *treeWalk()* and *randomWalk()* methods in *BatchAVLProver*


**2.0.2**
---------

* *generateProof()* -> *generateProofAndUpdateStorage()* in *PersistentBatchAVLProver*, new optional parameter 
for this method (to pass additional key-value pairs into storage)
* additional optional parameter for *PersistentBatchAVLProver* (with the same meaning as above)


**2.0.1**
---------

* Style fixes
* *version* method signature change in *VersionedAVLStorage*
* *rollbackVersions* method in *VersionedAVLStorage*
* *AdProof* was renamed to *SerializedAdProof*

**2.0.0**
---------

* Shapeless dependency removed
* Using tagged types instead of *Array[Byte]*, *suppertagged* microframework is used for that 
* BouncyCastle 1.58
* Rollback changes from 1.3.3

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
