package scorex.crypto.signing

import org.scalatest.prop.{GeneratorDrivenPropertyChecks, PropertyChecks}
import org.scalatest.{Matchers, PropSpec}
import scorex.crypto.encode.Base16
import scorex.crypto.signatures.{Curve25519, PrivateKey}


class SigningFunctionsSpecification extends PropSpec
  with PropertyChecks
  with GeneratorDrivenPropertyChecks
  with Matchers {

  property("signed message should be verifiable with appropriate public key") {
    forAll { (seed1: Array[Byte], seed2: Array[Byte],
              message1: Array[Byte], message2: Array[Byte]) =>
      whenever(!seed1.sameElements(seed2) && !message1.sameElements(message2)) {
        val keyPair = Curve25519.createKeyPair(seed1)
        val keyPair2 = Curve25519.createKeyPair(seed2)

        val sig = Curve25519.sign(keyPair._1, message1)

        Curve25519.verify(sig, message1, keyPair._2) shouldBe true
        Curve25519.verify(sig, message1, keyPair2._2) should not be true
        Curve25519.verify(sig, message2, keyPair._2) should not be true

      }
    }
  }

  property("shared secret should be same for both parties ") {

    forAll { (seed1: Array[Byte], seed2: Array[Byte]) =>
      whenever(!seed1.sameElements(seed2)) {
        val keyPair1 = Curve25519.createKeyPair(seed1)
        val keyPair2 = Curve25519.createKeyPair(seed2)

        val shared = Curve25519.createSharedSecret(keyPair1._1, keyPair2._2)
        val sharedWithKeysReversed = Curve25519.createSharedSecret(keyPair2._1, keyPair1._2)

        val badSharedSecret1 = Curve25519.createSharedSecret(PrivateKey @@ keyPair2._2, keyPair1._2)
        val badSharedSecret2 = Curve25519.createSharedSecret(PrivateKey @@ keyPair2._2, keyPair1._2)

        shared.sameElements(sharedWithKeysReversed) should be(true)

        badSharedSecret1.sameElements(shared) shouldNot be(true)

        badSharedSecret2.sameElements(shared) shouldNot be(true)
      }
    }
  }

  property("test vectors from https://tools.ietf.org/html/rfc8032#page-24 - test 1") {
    val privKey = PrivateKey @@ Base16.decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").get
    val message = Array[Byte]()
    val sig = Curve25519.sign(privKey, message)
    val specSig = Base16.decode("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e" +
      "39701cf9b46bd25bf5f0595bbe24655141438e7a100b").get
    sig.sameElements(specSig)
  }

  property("test vectors from https://tools.ietf.org/html/rfc8032#page-24 - test 2") {
    val privKey = PrivateKey @@ Base16.decode("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb").get
    val message = Base16.decode("72").get
    val sig = Curve25519.sign(privKey, message)
    val specSig = Base16.decode("92a009a9f0d4cab8720e820b5f642540" +
      "a2b27b5416503f8fb3762223ebdb69da" +
      "085ac1e43e15996e458f3613d0f11d8c" +
      "387b2eaeb4302aeeb00d291612bb0c00").get
    sig.sameElements(specSig)
  }

  property("test vectors from https://tools.ietf.org/html/rfc8032#page-24 - test 3") {
    val privKey = PrivateKey @@ Base16.decode("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7").get
    val message = Base16.decode("af82").get
    val sig = Curve25519.sign(privKey, message)
    val specSig = Base16.decode("6291d657deec24024827e69c3abe01a3" +
      "0ce548a284743a445e3680d7db5ac3ac" +
      "18ff9b538d16f290ae67f760984dc659" +
      "4a7c15e9716ed28dc027beceea1ec40a").get
    sig.sameElements(specSig)
  }

  property("test vectors from https://tools.ietf.org/html/rfc8032#page-24 - test 1024") {
    val privKey = PrivateKey @@ Base16.decode("f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5").get
    val message = Base16.decode("08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50" +
      "f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d65" +
      "8675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199e" +
      "e5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e06203b33890cc9b832f79ef80560cc" +
      "b9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd" +
      "7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5" +
      "aa3fb2d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187e" +
      "bb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd6" +
      "2481d9089beccf80cfe2df16a2cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27a" +
      "f87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c" +
      "144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297d07ad1" +
      "ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57" +
      "fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a" +
      "7e08d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd4" +
      "19c17a3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342" +
      "721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246" +
      "f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11" +
      "faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380db2eaaa707b4c4185c32eddcdd306705e4d" +
      "c1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0").get
    val sig = Curve25519.sign(privKey, message)
    val specSig = Base16.decode("0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ec" +
      "ea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03").get
    sig.sameElements(specSig)
  }

  property("test vectors from https://tools.ietf.org/html/rfc8032#page-24 - test SHA") {
    val privKey = PrivateKey @@ Base16.decode("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42").get
    val message = Base16.decode("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836" +
      "ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f").get
    val sig = Curve25519.sign(privKey, message)
    val specSig = Base16.decode("dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdf" +
      "bc7c66431e0303dca179c138ac17ad9bef1177331a704").get
    sig.sameElements(specSig)
  }
}