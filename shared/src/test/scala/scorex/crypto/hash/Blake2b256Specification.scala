package scorex.crypto.hash

class Blake2b256Specification extends HashTest {

  hashCheckString(Blake2b256,
    Map(
      "" -> "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
      "abc" -> "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"
    )
  )

}
