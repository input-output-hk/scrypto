package scrypto.signatures

trait EllipticCurveSignatureScheme[SizeT <: shapeless.Nat] extends SigningFunctions[SizeT]
