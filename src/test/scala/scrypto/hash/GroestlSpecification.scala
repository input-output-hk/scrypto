package scrypto.hash

class GroestlSpecification extends HashTest {

  hashCheckString(Groestl256,
    Map(
      "" -> "1a52d11d550039be16107f9c58db9ebcc417f16f736adb2502567119f0083467",
      "The quick brown fox jumps over the lazy dog" -> "8c7ad62eb26a21297bc39c2d7293b4bd4d3399fa8afab29e970471739e28b301"
    )
  )

  hashCheckString(Groestl512,
    Map(
      "" -> "6d3ad29d279110eef3adbd66de2a0345a77baede1557f5d099fce0c03d6dc2ba8e6d4a6633dfbd66053c20faa87d1a11f39a7fbe4a6c2f009801370308fc4ad8",
      "The quick brown fox jumps over the lazy dog" -> "badc1f70ccd69e0cf3760c3f93884289da84ec13c70b3d12a53a7a8a4a513f99715d46288f55e1dbf926e6d084a0538e4eebfc91cf2b21452921ccde9131718d"
    )
  )

}
