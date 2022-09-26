package scorex.crypto.hash


trait Blake2b[D <: Digest] extends BouncyCastleHash[D] {
  override protected lazy val digestFn = createBlake2bDigest(DigestSize * 8)
}



