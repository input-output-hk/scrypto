package scorex.crypto

import scorex.crypto.hash.unsafeCast

import scala.language.implicitConversions

//import supertagged.TaggedType

package object authds {

//  type LeafData = LeafData.Type
//  type Side = Side.Type
//  type ADKey = ADKey.Type
//  type ADValue = ADValue.Type
//  type ADDigest = ADDigest.Type
//  type SerializedAdProof = SerializedAdProof.Type
//  type Balance = Balance.Type

  case class LeafData(val value: Array[Byte]) extends AnyVal
  implicit def leafDataToArray(data: LeafData): Array[Byte] = data.value

  case class Side(val value: Byte) extends AnyVal
  implicit def sideToArray(data: Side): Byte = data.value
  case class ADKey(val value: Array[Byte]) extends AnyVal
  implicit def adkeyToArray(data: ADKey): Array[Byte] = data.value
  case class ADValue(val value: Array[Byte]) extends AnyVal
  implicit def advalueToArray(data: ADValue): Array[Byte] = data.value
  case class ADDigest(val value: Array[Byte]) extends AnyVal
  implicit def addigestToArray(data: ADDigest): Array[Byte] = data.value
  case class SerializedAdProof(val value: Array[Byte]) extends AnyVal
  implicit def adproofToArray(data: SerializedAdProof): Array[Byte] = data.value
  case class Balance(val value: Byte) extends AnyVal
  implicit def balanceToArray(data: Balance): Byte = data.value

  // object LeafData extends TaggedType[Array[Byte]]
//
//  object Side extends TaggedType[Byte]
//
//  object ADKey extends TaggedType[Array[Byte]]
//
//  object ADValue extends TaggedType[Array[Byte]]
//
//  object ADDigest extends TaggedType[Array[Byte]]
//
//  object SerializedAdProof extends TaggedType[Array[Byte]]
//
//  object Balance extends TaggedType[Byte]

  /** Immutable empty array which can be used in many places to avoid allocations. */
  val EmptyByteArray = Array.empty[Byte]
}
