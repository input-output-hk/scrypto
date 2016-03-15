package scorex.crypto.signatures

import java.lang.reflect.Constructor

import org.slf4j.LoggerFactory
import org.whispersystems.curve25519.OpportunisticCurve25519Provider
import scorex.crypto.hash.Sha256

import scala.util.{Failure, Try}


class Curve25519 extends EllipticCurve {

  import SigningFunctions._

  override val SignatureLength = 64
  override val KeyLength = 32
  private val provider: OpportunisticCurve25519Provider = {
    val constructor = classOf[OpportunisticCurve25519Provider]
      .getDeclaredConstructors
      .head
      .asInstanceOf[Constructor[OpportunisticCurve25519Provider]]
    constructor.setAccessible(true)
    constructor.newInstance()
  }

  //todo: dirty hack, switch to logic as described in WhisperSystem's Curve25519 tutorial
  //todo: when it'll be possible to pass a random seed from outside
  //todo: https://github.com/WhisperSystems/curve25519-java/pull/7

  override def createKeyPair(seed: Array[Byte]): (PrivateKey, PublicKey) = {
    val hashedSeed = Sha256.hash(seed)
    val privateKey = provider.generatePrivateKey(hashedSeed)
    privateKey -> provider.generatePublicKey(privateKey)
  }

  override def sign(privateKey: PrivateKey, message: MessageToSign): Signature = {
    require(privateKey.length == KeyLength)
    provider.calculateSignature(provider.getRandom(SignatureLength), privateKey, message)
  }

  override def verify(signature: Signature, message: MessageToSign, publicKey: PublicKey): Boolean = Try {
    require(signature.length == SignatureLength)
    require(publicKey.length == KeyLength)
    provider.verifySignature(publicKey, message, signature)
  }.recoverWith { case e =>
    log.debug("Error while message signature verification", e)
    Failure(e)
  }.getOrElse(false)

  protected def log = LoggerFactory.getLogger(this.getClass)
}