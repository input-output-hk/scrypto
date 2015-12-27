#Introducing Scrypto
Scrypto is an open source cryptographic toolkit designed to make it easier and safer for developers to use cryptography in their applications.

## Get Scrypto

Scrypto is available on Sonatype for Scala 2.11!
```scala
resolvers += "Sonatype Releases" at "https://oss.sonatype.org/content/repositories/releases/"
```
You can use Scrypto in your sbt project by simply adding the following dependency to your build file:
```scala
libraryDependencies += "org.consensusresearch" %% "scrypto" % "1.0.2"
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

### Encode
- Base58

### Signing functions
- Curve25519
