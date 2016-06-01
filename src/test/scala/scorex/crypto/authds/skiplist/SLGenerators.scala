package scorex.crypto.authds.skiplist

import org.scalacheck.{Arbitrary, Gen}

trait SLGenerators {

  val noneEmptyBytes: Gen[Array[Byte]] = for {
    key: Array[Byte] <- Arbitrary.arbitrary[Array[Byte]] if key.length < SLElement.MaxKeySize && key.length > 0
  } yield key

  val optionBytes: Gen[Option[Array[Byte]]] = for {
    bytes: Array[Byte] <- noneEmptyBytes
    op: Boolean <- Arbitrary.arbitrary[Boolean]
  } yield if (op) Some(bytes) else None

  val slelementGenerator: Gen[SLElement] = for {
    key: Array[Byte] <- noneEmptyBytes
    value: Array[Byte] <- Arbitrary.arbitrary[Array[Byte]]
  } yield SLElement(key, value)

  val slnodeGenerator: Gen[SLNode] = for {
    el <- slelementGenerator
    rightKey: Option[Array[Byte]] <- optionBytes
    downKey: Option[Array[Byte]] <- optionBytes
    level: Int <- Arbitrary.arbitrary[Int] if level >= 0
    isTower: Boolean <- Arbitrary.arbitrary[Boolean]
  } yield SLNode(el, rightKey, downKey, level, isTower: Boolean)
}
