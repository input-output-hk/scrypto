#Introducing Scrypto
Scrypto is an open source cryptographic toolkit designed to make it easier and safer for developers to use cryptography in their applications.

## Get Scrypto

Scrypto is available on Sonatype for Scala 2.11!
You can use Scrypto in your sbt project by simply adding the following dependency to your build file:

```scala
libraryDependencies += "org.consensusresearch" %% "scrypto" % "+"
```

### Hash functions
Supported hash algorithms are:
- Blake
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
Sha256.hash("test")
```

Create your own hash chain algorithm

```scala
import scorex.crypto.hashChain
object MyCustomHash extends CryptographicHash {
  override val DigestSize: Int = 64
  override def hash(input: Message): Digest = hashChain(input, Blake512, BMW512, Groestl512, Skein512, Sha512)
}
```

### Encode
- Base58

