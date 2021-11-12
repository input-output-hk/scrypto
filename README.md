# Scrypto [![Build Status](https://travis-ci.org/input-output-hk/scrypto.svg?branch=master)](https://travis-ci.org/input-output-hk/scrypto)

Scrypto is an open source cryptographic toolkit designed to make it easier and safer for developers to use cryptography in their applications.

It was extracted from [Scorex](https://github.com/ScorexProject/Scorex-Lagonaki), open-source modular blockchain & cryptocurrency framework.

Public Domain.

**If you want to check benchmarks for authenticated AVL+ trees, please visit [dedicated repository](https://github.com/input-output-hk/scrypto-benchmarks).
Use the repository as code examples for the trees also, though one code example is provided in "Authenticated Data Structures" section below.**

## Get Scrypto

Scrypto is available on Sonatype for Scala 2.12:
```scala
resolvers += "Sonatype Releases" at "https://oss.sonatype.org/content/repositories/releases/"
```

You can use Scrypto in your sbt project by simply adding the following dependency to your build file:
```scala
libraryDependencies += "org.scorexfoundation" %% "scrypto" % "2.2.0"
```

### Hash functions

Supported hash algorithms are:
- Blake2b
- Keccak
- Sha
- Whirlpool
- Skein
- Stribog
       
Take a look at CryptographicHash interface and use supported hash algorithms like
```scala
Keccak512("some string or bytes")
```
All provided hash functions are secure, and their implementations are thread safe.

### Commutative hash

You can create commutative hash from any hash function with `CommutativeHash` case class like `CommutativeHash(Sha256)`.
A hash function h is commutative if h(x,y)==h(y,x) , for all x and y.

### Binary-to-text Encoding Schemes

Scrypto has implementations of few binary-to-text encoding schemes:

- Base16
- Base58
- Base64

Example:

```scala
  val encoded = Base64.encode(data)
  val restored = Base64.decode(encoded)
  restored shouldBe data
```

### Signing functions

Scrypto supports following elliptic curves:

- Curve25519(& Ed25519)

Example:

```scala
  val curveImpl = new Curve25519
  val keyPair = curveImpl.createKeyPair()
  val sig = curveImpl.sign(keyPair._1, message)
  assert(curveImpl.verify(sig, message, keyPair._2))
```

**Note on security:** Scrypto provides a simple Scala wrapper for [Curve25519-Java](https://github.com/WhisperSystems/curve25519-java) by
Whisper Systems, so has the same security properties. JDK's SecureRandom is used to obtain seed bytes.

### Authenticated data structures

Scrypto supports two-party authenticated AVL+ trees with the batching compression support and guaranteed verifier efficiency, as described in http://eprint.iacr.org/2016/994. 
The implementation can be found in the `scorex.crypto.authds.avltree.batch` package. 


The overall approach is as follows. The prover has a data structure of (key, value) pairs
and can perform operations on it using `performOneOperation` method. An operation (see `scorex.crypto.authds.avltree.batch.Operation`) is either a lookup or a modification.
 We provide sample modifications (such as insertions, removals, and additions/subtractions from the value of a given key), but users of this code may define their own (such as subtractions that allow negative values, unlike our subtractions). A modification may be defined to fail under certain conditions (e.g., a deletion of a key that is not there, or a subtraction that results in a negative value), in which case the tree is not modified. If the operation succeeds, it returns the value associated with the key before the operation was performed. The prover can compute the digest of the current state of the data structure via the `digest` method. At any point the prover may use `generateProof`, which will produce a proof covering the batch of operations (except the ones that failed) since the last `generateProof`. 

The verifier is constructed from the digest that preceeded the latest batch of operations and the proof for the latest batch. The verifier can also be given optional parameters for the maximum number of operations (and at most how many of those are deletions) in order to guarantee a bound on the verifier running time in case of a malicious proof, thus mitigating denial of service attacks. Once constructed, the verifier can replay the same sequence of operations to compute the new digest and to be assured that the operations do not fail and their return values are correct. Note that the verifier is not assured that the sequence of operations is the same as the one the prover performed---it is assumed that the prover and verifier agree on the sequence of operations (two-party authenticated data structures are useful when the prover and verifier agree on the sequence of operations). However, if the verifier digest matches the prover digest after the sequence of operations, then the verifier is assured that the state of the data structure is the same, regardless of what sequence of operations led to this state.

We also provide `unauthenticatedLookup` for the prover, in order to allow the prover to look up values in the data structure without affecting the proof. 

Here are code examples for generating proofs and checking them. In this example we demonstrate two batches of operations, starting with the empty tree. In the first batch, a prover inserts three values into the tree; in the second batch, the prover changes the first value, attempts to subtract too much from the second one, which fails, looks up the third value, and attempts to delete a nonexisting value, which also fails. We use 1-byte keys for simplicity; in a real deployment, keys would be longer.
 
* First, we create a prover and get an initial digest from it (in a real application, this value is a public constant because anyone, including verifiers, can compute it by using the same two lines of code)

```scala
  import com.google.common.primitives.Longs
  import scorex.crypto.authds.{ADKey, ADValue}
  import scorex.crypto.authds.avltree.batch._
  import scorex.crypto.hash.{Blake2b256, Digest32}

  val prover = new BatchAVLProver(keyLength = 1, valueLengthOpt = Some(8))
  val initialDigest = prover.digest
```        


* Second, we create the first batch of tree modifications, inserting keys 1, 2, and 3 with values 10, 20, and 30. We use `com.google.common.primitives.Longs.toByteArray` to get 8-byte values out of longs.

```scala
  val key1 = Array(1:Byte)
  val key2 = Array(2:Byte)
  val key3 = Array(3:Byte)
  val op1 = Insert(ADKey @@ key1, ADValue @@ Longs.toByteArray(10))
  val op2 = Insert(ADKey @@ key2, ADValue @@ Longs.toByteArray(20))
  val op3 = Insert(ADKey @@ key3, ADValue @@ Longs.toByteArray(30))
```
    
* The prover applies the three modifications to the empty tree, obtains the first batch proof, and announces the next digest `digest1`.
    
```scala    
  prover.performOneOperation(op1) // Returns Success(None)
  prover.performOneOperation(op2) // Returns Success(None)
  prover.performOneOperation(op3) // Returns Success(None)
  val proof1 = prover.generateProof()
  val digest1 = prover.digest
```    
      
* A proof is just an array of bytes, so you can immediately send it over a wire or save it to a disk. 

* Next, the prover attempts to perform five more modifications: changing the first value to 50, subtracting 40 from the second value (which will fail, because our UpDateLongBy operation is designed to fail on negative values), looking up the third value, deleting the key 5 (which will also fail, because key 5 does not exist), and deleting the third value. After the four operations, the prover obtains a second proof, and announces the new digest `digest2` 

```scala
  val op4 = Update(ADKey @@ key1, ADValue @@ Longs.toByteArray(50))
  val op5 = UpdateLongBy(ADKey @@ key2, -40)
  val op6 = Lookup(ADKey @@ key3)
  val op7 = Remove(ADKey @@ Array(5:Byte))
  val op8 = Remove(ADKey @@ key3)
  prover.performOneOperation(op4) // Returns Success(Some(Longs.toByteArray(10)))
  // Here we can, for example, perform prover.unauthenticatedLookup(key1) to get 50
  // without affecting the proof or anything else
  prover.performOneOperation(op5) // Returns Failure
  prover.performOneOperation(op6) // Returns Success(Some(Longs.toByteArray(30)))
  prover.performOneOperation(op7) // Returns Failure
  prover.performOneOperation(op8) // Returns Success(Some(Longs.toByteArray(30)))
  val proof2 = prover.generateProof() // Proof only for op4 and op6
  val digest2 = prover.digest
```

* We now verify the proofs. For each batch, we first construct a verifier using the digest that preceded the batch and the proof of the batch; we also supply an upper bound on the number of operations in the batch and an upper bound on how many of those operations are deletions. Note that the number of operations can be None, in which case there is no guaranteed running time bound; furthermore, the number of deletions can be None, in which case the guaranteed running time bound is not as small as it can be if a good upper bound on the number of deletion is supplied. 

* Once the verifier for a particular batch is constructed, we perform the same operations as the prover, one by one (but not the ones that failed for the prover). If verification fails at any point (at construction time or during an operation), the verifier digest will equal None from that point forward, and no further verifier operations will change the digest.  Else, the verifier's new digest is the correct one for the tree as modified by the verifier. Furthermore, if the verifier performed the same modifications as the prover, then the verifier and prover digests will match.

```scala
  val verifier1 = new BatchAVLVerifier[Digest32, Blake2b256.type](initialDigest, proof1, keyLength = 1, valueLengthOpt = Some(8), maxNumOperations = Some(2), maxDeletes = Some(0))
  verifier1.performOneOperation(op1) // Returns Success(None)
  verifier1.performOneOperation(op2) // Returns Success(None)
  verifier1.performOneOperation(op3) // Returns Success(None)
  verifier1.digest match {
    case Some(d1) if d1.sameElements(digest1) =>
      //If digest1 from the prover is already trusted, then verification of the second batch can simply start here
      val verifier2 = new BatchAVLVerifier[Digest32, Blake2b256.type](d1, proof2, keyLength = 1, valueLengthOpt = Some(8), maxNumOperations = Some(3), maxDeletes = Some(1))
      verifier2.performOneOperation(op4) // Returns Success(Some(Longs.toByteArray(10)))
      verifier2.performOneOperation(op6) // Returns Success(Some(Longs.toByteArray(30)))
      verifier2.performOneOperation(op8) // Returns Success(Some(Longs.toByteArray(30)))
      verifier2.digest match {
        case Some(d2) if d2.sameElements(digest2) => println("first and second digest value and proofs are valid")
        case _ => println("second proof or announced digest NOT valid")
      }
    case _ =>
      println("first proof or announced digest NOT valid")
  }
```

# Merkle Tree

[TODO: describe MerkleTree & MerkleProof classes]

# Tests

Run `sbt test` from a folder containing the framework to launch tests.

# Benchmarks

Run `sbt bench:test` from a folder containing the framework to launch embedded benchmarks.

# License

The code is under Public Domain CC0 license means you can do anything with it. Full license text is in [COPYING file](https://github.com/ScorexProject/scrypto/blob/master/COPYING)

# Contributing

Your contributions are always welcome! Please submit a pull request or create an issue to add a new cryptographic primitives or better implementations.
