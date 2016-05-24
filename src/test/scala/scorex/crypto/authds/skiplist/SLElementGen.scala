package scorex.crypto.authds.skiplist

import org.scalacheck.{Arbitrary, Gen}

trait SLElementGen {

  val slelementGenerator: Gen[SLElement] = for {
    key: Array[Byte] <- Arbitrary.arbitrary[Array[Byte]] if key.length < SLElement.MaxKeySize && key.length > 0
    value: Array[Byte] <- Arbitrary.arbitrary[Array[Byte]]
  } yield SLElement(key, value)

}
