package scorex

package object utils {

  @deprecated("Use scorex.util.ScorexEncoding instead.", "scorex-util 0.1.1")
  type ScorexEncoding = scorex.util.ScorexEncoding

  // from supertagged source
  @inline final def unsafeCast[A, B](v: A): B = v.asInstanceOf[B]
//  @inline final def safeCast[A <: AnyVal { val value: B }, B](v: A): B = v.value
}
