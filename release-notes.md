**1.2.3**
---------



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
