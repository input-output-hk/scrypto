package scorex.crypto.hash

import scorex.utils.HashHelpers


object X11 extends CryptographicHash32 {

  override def hash(input: Message): Digest = HashHelpers.applyHashes(input,
    Blake512, BMW512, Groestl512, Skein512, JH512, Keccak512, Luffa512, CubeHash512, SHAvite512, SIMD512, ECHO512)
    .slice(0, DigestSize)
}
