# Scrypto [![Build Status](https://travis-ci.org/input-output-hk/scrypto.svg?branch=master)](https://travis-ci.org/input-output-hk/scrypto)

Scrypto is an open source cryptographic toolkit designed to make it easier and safer for developers to use cryptography in their applications.

It was extracted from [Scorex](https://github.com/ScorexProject/Scorex-Lagonaki), open-source modular blockchain & cryptocurrency framework.

Public Domain.

**If you want to check benchmarks for authenticated AVL+ trees, please visit [dedicated repository](https://github.com/input-output-hk/scrypto-benchmarks).
Use the repository as code examples for the trees also, though one code example is provided in "Authenticated Data Structures" section below.**

## Get Scrypto

Scrypto is available on Sonatype for Scala 2.11!
```scala
resolvers += "Sonatype Releases" at "https://oss.sonatype.org/content/repositories/releases/"
```

You can use Scrypto in your sbt project by simply adding the following dependency to your build file:
```scala
libraryDependencies += "org.consensusresearch" %% "scrypto" % "1.1.0"
```

### Hash functions

Supported hash algorithms are:
- Blake
- Blake2b
- BMW
- CubeHash
- Echo
- Fugue
- Groestl
- Hamsi
- JH
- Keccak
- Luffa
- Sha
- SHAvite
- SIMD
- Skein
- Whirlpool
       
Take a look at CryptographicHash interface and use supported hash algorithms like
```scala
Keccak512("some string or bytes")
```
All provided hash functions are secure, and their implementations are thread safe.

### Hash chain

It's possible to apply hash functions sequentially to create more secure hash function. The most well-known [X11](http://en.wiki.dashninja.pl/wiki/X11) hash chain is available from this library.

You can easily create your own hash chain function:
```scala
import scorex.crypto.applyHashes
object MyCustomHash extends CryptographicHash {
  override val DigestSize: Int = 64
  override def hash(input: Message): Digest = applyHashes(input, Blake512, Sha512, Groestl512, Skein512)
}
```
or just
```scala
val myHashChain = hashChain(Blake512, BMW512, Groestl512, Skein512, JH512, Keccak512, Luffa512, Wirlpool)
```
Note, that hash chain will be as good as the [strongest](https://en.wikipedia.org/wiki/Cryptographic_hash_function#Concatenation_of_cryptographic_hash_functions) of the algorithms included in the chain.

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

**Note on security:** Scrypto provides Scala wrapper for [Curve25519-Java](https://github.com/WhisperSystems/curve25519-java) by
Whisper Systems, so has the same security properties. JDK's SecureRandom used to obtain seed bytes.

### Authenticated data structures

Scrypto supports authenticated AVL+ trees with the batching compression support and guaranteed verifier efficiency, see http://eprint.iacr.org/2016/994 for details. 
The implementation can be found in the `scorex.crypto.authds.avltree.batch` package. Here are code snippets on how to generate
proofs and check them. In this example we demonstrate two batches of two modifications per batch, starting with the empty tree: in the first batch, a prover inserts two values 
into the tree; in the second batch, the prover updates the first value and deletes the second one.
 
* First, we create a prover and get an initial root hash from it (in a real application, this value is a public
constant because anyone, including verifiers, can compute it by using the same two lines of code)

```scala
  val prover = new BatchAVLProver(keyLength = 1, valueLength = 8)
  val initRoot = prover.rootHash
```        


* Second, we create the first batch of tree modifications, inserting keys 1 and 2 with values 0 for each 

```scala
  val m1 = Insert(Array(1:Byte), Array.fill(8)(0:Byte))
  val m2 = Insert(Array(2:Byte), Array.fill(8)(0:Byte))
```
    
* Prover applies the two modifications to an empty tree, obtains the first batch proof, and announces the next root hash `root1`
    
```scala    
  prover.performOneModification(m1)
  prover.performOneModification(m2)
  val proof1 = prover.generateProof
  val root1 = prover.rootHash
```    
      
* A proof is just an array of bytes, so you can immediately send it over a 
wire or save it to a disk. Next, the prover performs two more modifications, obtains a second proof, and announces the second
root hash `root2` 

```scala
   val m3 = Update(Array(1:Byte), Array.fill(8)(1:Byte))
   val m4 = Remove(Array(2:Byte))
   prover.performOneModification(m3)
   prover.performOneModification(m4)
   val proof2 = prover.generateProof
   val root2 = prover.rootHash
```

* We now verify the proofs. For each batch, we construct a verifier using the digest
that preceded the batch and the proof of the batch, and apply modifications. 
If verification fails, the verifier digest will equal None.  Else, the verifier's new digest
is the correct one for the tree as modified by the verifier. Furthermore, if the verifier
performed the same modifications as the prover, then the verifier and prover digests will match.

```scala
  val verifier1 = new BatchAVLVerifier(initRoot, proof1, keyLength = 1, valueLength = 8)
  verifier1.performOneModification(m1)           
  verifier1.performOneModification(m2)
  verifier1.digest match {
    case Some(rt1) if rt1.sameElements(root1) =>
      //If announced root1 is already trusted, then verification of the second batch can simply start here
      val verifier2 = new BatchAVLVerifier(rt1, proof2, keyLength = 1, valueLength = 8)
      verifier2.performOneModification(m3)
      verifier2.performOneModification(m4)
      verifier2.digest match {
        case Some(rt2) if rt2.sameElements(root2) => println("declared root2 value and proofs are valid")
        case _ => println("second proof or announced root value NOT valid")
      }
    case _ =>
      println("first proof or announced root1 NOT valid")
  }
```

Note that the verifier has additional optional parameters that can be used to limit its maximum running time, to prevent
a malicious prover from forcing the verifier to waste cycles.

# Tests

Run `sbt test` from a folder contains the framework to launch tests.

# License

The code is under Public Domain CC0 license means you can do anything with it. Full license text is in [COPYING file](https://github.com/ScorexProject/scrypto/blob/master/COPYING)

# Contributing

Your contributions are always welcome! Please submit a pull request or create an issue to add a new cryptographic primitives or better implementations.
