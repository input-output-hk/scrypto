package scorex.crypto.signatures

import java.security.SecureRandom

import shapeless.Sized

trait SigningFunctions[SizeT <: shapeless.Nat] {

  import SigningFunctions._

  type SignedSignature = Sized[Array[Byte], SizeT]

  val SignatureLength: Int
  val KeyLength: Int

  def createKeyPair(seed: Array[Byte]): (PrivateKey, PublicKey)

  def createKeyPair: (PrivateKey, PublicKey) = {
    val seed = new Array[Byte](KeyLength)
    new SecureRandom().nextBytes(seed) // modifies seed
    createKeyPair(seed)
  }

  def sign(privateKey: PrivateKey, message: MessageToSign): Signature

  def signSized(privateKey: PrivateKey, message: MessageToSign): SignedSignature = Sized.wrap(sign(privateKey, message))

  def verify(signature: Signature, message: MessageToSign, publicKey: PublicKey): Boolean

  def verify(signature: SignedSignature, message: MessageToSign, publicKey: PublicKey): Boolean = {
    verify(signature.unsized, message, publicKey)
  }

  def createSharedSecret(privateKey: PrivateKey, publicKey: PublicKey): SharedSecret
}

object SigningFunctions {
  type PrivateKey = Array[Byte]
  type PublicKey = Array[Byte]
  type Signature = Array[Byte]
  type MessageToSign = Array[Byte]
  type SharedSecret = Array[Byte]
}