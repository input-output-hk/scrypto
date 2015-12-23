#Introducing Scrypto
Scrypto is an open source cryptographic toolkit designed to make it easier and safer for developers to use cryptography in their applications.

## Get Scrypto

Scrypto is available on Sonatype for Scala 2.11!
You can use Scrypto in your sbt project by simply adding the following dependency to your build file:

```scala
libraryDependencies += "org.consensusresearch" %% "scrypto" % "+"
```

### Hash functions
Supported hash functions are:
- Sha256
- Ripemd160

Take a look at CryptographicHash interface and use them like
```scala
Sha256.hash("test")
```

### Encode
- Base58

