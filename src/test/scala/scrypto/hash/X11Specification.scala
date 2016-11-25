package scrypto.crypto.hash

class X11Specification extends HashTest {

  hashCheck(X11,
    Map(
      emptyBytes -> "51b572209083576ea221c27e62b4e22063257571ccb6cc3dc3cd17eb67584eba",
      Array(1: Byte, 2:Byte) -> "7da4f0784f6c77fec6931cd3590819963de0c50e22b1faf14cd3b5de1aa2871d"
    )
  )

}
