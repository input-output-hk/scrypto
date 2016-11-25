package scrypto.crypto.hash

class ShaSpecification extends HashTest {

  hashCheckString(Sha256,
    Map(
      "hello world" -> "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
      "" -> "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "abc" -> "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" -> "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    )
  )

  hashCheckString(Sha512,
    Map(
      "hello world" -> "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f",
      "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f1" -> "eedf5a9abf721bccbaf547ae5a26b29382043ed97c92a7b1fee75233115d681ffa537dfe644f66e80bd2537584f0829484eb8c8dc6b26d11811915025cf29f84"
    )
  )

}
