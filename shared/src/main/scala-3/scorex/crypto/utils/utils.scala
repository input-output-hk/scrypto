package scorex.crypto

object utils:
  trait NewType[A]:
    opaque type Type <: A = A

    inline def @@(a: A): Type = a
    inline def @@@[B <: A](b: B): Type = b

    extension (a: Type) inline def value: A = a

    given conversion: Conversion[Type, A] = (_.value)
    given (using CanEqual[A, A]): CanEqual[Type, Type] = CanEqual.derived
  end NewType