package scorex.crypto

object utils:

  trait NewDigest:
    opaque type Type <: Array[Byte] = Array[Byte] with this.type
    inline def @@(a: Array[Byte]): this.Type = a.asInstanceOf[this.Type]
    inline def @@@[B <: Array[Byte]](b: B): this.Type = b.asInstanceOf[this.Type]
  end NewDigest

  trait NewArrayByte:
    opaque type Type <: Array[Byte] = Array[Byte]
    inline def @@(a: Array[Byte]): this.Type = a
    inline def @@@[B <: Array[Byte]](b: B): this.Type = b
  end NewArrayByte

  trait NewByte:
    opaque type Type <: Byte = Byte
    inline def @@(a: Byte): this.Type = a
    inline def @@@[B <: Byte](b: B): this.Type = b
  end NewByte