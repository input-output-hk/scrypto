package scrypto.crypto.hash

class CubeHashSpecification extends HashTest {

  hashCheckString(CubeHash256,
    Map(
      "Hello" -> "e712139e3b892f2f5fe52d0f30d78a0cb16b51b217da0e4acb103dd0856f2db0",
      "The quick brown fox jumps over the lazy dog" -> "5151e251e348cbbfee46538651c06b138b10eeb71cf6ea6054d7ca5fec82eb79"
    )
  )

  hashCheckString(CubeHash512,
    Map(
      "Hello" -> "dcc0503aae279a3c8c95fa1181d37c418783204e2e3048a081392fd61bace883a1f7c4c96b16b4060c42104f1ce45a622f1a9abaeb994beb107fed53a78f588c",
      "The quick brown fox jumps over the lazy dog" -> "bdba44a28cd16b774bdf3c9511def1a2baf39d4ef98b92c27cf5e37beb8990b7cdb6575dae1a548330780810618b8a5c351c1368904db7ebdf8857d596083a86"
    )
  )

}
