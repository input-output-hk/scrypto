package scorex.crypto.signatures

import java.security.SecureRandom

trait SigningFunctions {

  import SigningFunctions._


  val SignatureLength: Int
  val KeyLength: Int

  def createKeyPair(seed: Array[Byte]): (PrivateKey, PublicKey)

  def createKeyPair: (PrivateKey, PublicKey) = {
    val seed = new Array[Byte](KeyLength)
    new SecureRandom().nextBytes(seed) // modifies seed
    createKeyPair(seed)
  }

  def sign(privateKey: PrivateKey, message: MessageToSign): Signature

  def verify(signature: Signature, message: MessageToSign, publicKey: PublicKey): Boolean

  def createSharedSecret(privateKey: PrivateKey, publicKey: PublicKey): SharedSecret
}

object SigningFunctions {
  type PrivateKey = Array[Byte]
  type PublicKey = Array[Byte]
  type Signature = Array[Byte]
  type MessageToSign = Array[Byte]
  type SharedSecret = Array[Byte]
}