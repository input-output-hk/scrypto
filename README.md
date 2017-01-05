# Scrypto [![Build Status](https://travis-ci.org/input-output-hk/scrypto.svg?branch=master)](https://travis-ci.org/input-output-hk/scrypto)

Scrypto is an open source cryptographic toolkit designed to make it easier and safer for developers to use cryptography in their applications.

It was extracted from [Scorex](https://github.com/ScorexProject/Scorex-Lagonaki), open-source modular blockchain & cryptocurrency framework.

Public Domain.

**If you want to check benchmarks for authenticated AVL+ trees, please visit [dedicated repository](https://github.com/input-output-hk/scrypto-benchmarks).**

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

### Authenticated data structure

Scrypto supports following authenticated data structures:

- Treap
- AVL+ tree

According our tests for dynamic data AVL+ trees performs better, see http://eprint.iacr.org/2016/994. The implementation
of AVL+ trees with batching compression can be found in the `scorex.crypto.authds.avltree.batch` package. For usage scenarios,
 see benchmarks in the [dedicated repository](https://github.com/input-output-hk/scrypto-benchmarks). 

# Tests

Run `sbt test` from a folder contains the framework to launch tests.

# License

The code is under Public Domain CC0 license means you can do anything with it. Full license text is in [COPYING file](https://github.com/ScorexProject/scrypto/blob/master/COPYING)

# Contributing

Your contributions are always welcome! Please submit a pull request or create an issue to add a new cryptographic primitives or better implementations.
