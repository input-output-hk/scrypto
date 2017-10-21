package scorex.crypto.hash

class KeccakSpecification extends HashTest {
  hashCheckString(Keccak256,
    Map(
      "" -> "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
     // "The quick brown fox jumps over the lazy dog" -> "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15"
    )
  )

  hashCheckString(Keccak512,
    Map(
      "" -> "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e",
      "The quick brown fox jumps over the lazy dog" -> "d135bb84d0439dbac432247ee573a23ea7d3c9deb2a968eb31d47c4fb45f1ef4422d6c531b5b9bd6f449ebcc449ea94d0a8f05f62130fda612da53c79659f609"
    )
  )
}
