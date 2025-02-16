package scorex.crypto.authds.avltree.batch

import org.scalacheck.{Gen, Arbitrary}
import org.scalatest.propspec.AnyPropSpec
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks
import scorex.crypto.authds.legacy.avltree.AVLTree
import scorex.crypto.authds._
import scorex.util.encode.{Base58, Base16}
import scorex.crypto.hash._
import scorex.utils.{Random, ByteArray, Longs}

import scala.util.Random.{nextInt => randomInt}
import scala.util.{Try, Failure}

class AVLBatchSpecification extends AnyPropSpec with ScalaCheckDrivenPropertyChecks with TwoPartyTests
  with BatchTestingHelpers {

  property("return removed leafs and internal nodes for small tree") {
    /**
      * manual check, that correct leafs and internal nodes where deleted
      * ______________top(V9WUMj6P,ES5Rnuf1)                                         top2(5VjCEAdt,2VT2d2nG)
      * __________________/           \                                                       /   \
      * NInf(11111111,ChyvjCc9)    right(5VjCEAdt,26ouau2w)       =>   NInf(11111111,DuQAiTxk)     Leaf1(5VjCEAdt,A889CP2P)
      * __________________________________/     \
      * __________Leaf0(V9WUMj6P,Fx5gbhBF)      Leaf1(5VjCEAdt,A889CP2P)
      **/
    val prover = generateProver(2)._1
    val top = prover.topNode.asInstanceOf[InternalProverNode[D]] // V9WUMj6P,ES5Rnuf1
    val negativeInfinity = top.left.asInstanceOf[ProverLeaf[D]] // 11111111,ChyvjCc9
    val right = top.right.asInstanceOf[InternalProverNode[D]] // 5VjCEAdt,26ouau2w
    val leaf0 = right.left.asInstanceOf[ProverLeaf[D]] // V9WUMj6P,Fx5gbhBF
    val leaf1 = right.right.asInstanceOf[ProverLeaf[D]] // 5VjCEAdt,A889CP2P

    val all = Seq(leaf1, top, right, leaf0, negativeInfinity)
    all.foreach(n => prover.contains(n) shouldBe true)
    val removedManual = all.tail

    prover.performOneOperation(Remove(leaf0.key))
    prover.performOneOperation(Lookup(leaf1.key))
    val removed = prover.removedNodes()

    // Top, Right and Leaf0 are not on the path any more, NegativeInfinity.newNextLeafKey changed.
    // Leaf1 is not affected
    removed.length shouldBe removedManual.length
    removedManual.foreach(n => removed.exists(_.label sameElements n.label) shouldBe true)
    prover.generateProof()
  }

  property("removedNodes() special case") {
    val prover = generateProver(0)._1
    implicit def strToKey(str: String): ADKey = ADKey @@ Base16.decode(str).get

    implicit def strToValue(str: String): ADValue = ADValue @@ Base16.decode(str).get

    val in = List(Insert("333724f1e5ed593ff3760e2fd14257e53320fcaba195198fe364c18317c8357a","e6e95bbc282023dc0f319a10a4166099"), Insert("70dc695bd7fb4f8d40f69cd82e6d704f219b7d49efee7856a54b809019bcb281","aab1db7e6768e75c360d6145563913a4"), Insert("ccdee12ce7d48bce1f2f3b237dafb03fe89109da05ad3e86ca1add4a969c6f11","3e1f7320a5560a034e37a51d7f2a5187"), Insert("71eb525ad833b9ac5e35feed6a4e663125cf764069a4c4bc69e135b19b84fc20","cc688ec7736770ba2cde8e8e43ef4730"), Insert("0f09f7704ed285c56154a2f7aef6eadde3e0faf9f3f07bb84393d7f83f8f9669","62116adc67d12aea779cf2eadb8854ea"), Insert("e73879715ba969d9f2f2ec1970ce379fec7e770e570e9fd454714ed874039236","e1fdbb6a2e7045c44d251b35822b8f9c"), Insert("66566ba505b632ce2fe70973bd2f695f62ca61edf78dd855424e1b80ed9db7ef","2bb222b9e052ce69246c4461975e7fef"), Insert("c2b09394bfffe27d5c1b8ba6f67bd489b499864531c85e3c3684821f6e38729d","9630dba1be5b809073bab215ad32d0ce"), Insert("fcca30ec0255f4117b71bb705f7f2e59e7222774da1dfae72c5ba032330c457a","f6d131b192aa421d444fd4e5b6088428"), Insert("f8d58130ccca6981df20ec8117039e390031dbe7caee3453d18b08d8df860709","6912d475249221a947c31a7c435a111f"), Insert("e0723e441695e2886e2450999a996788595dea7d25e508209a14472e06f68b36","42e6f2e681d979097205822d73b9fc4c"), Insert("628181857476ed88dcbf0d77c460b8626cd968a9bdf43c1d2ea67f2acd3694d3","940746265213123f4149a49ebad3030a"), Insert("4a83fefebe881f26974969c3127ebbfe711358cb89465bc3b186f895bcd61f5e","e77b0de31e457f58318a65fc169060e5"), Insert("0d58e0cda79b82eddf8d518d4a1addf5a92447091d78bcecdb727ab0c81d7a7b","9b01651c3362cc1964f81f3af4c73aea"), Insert("bb13eaafd61c429894899d4ed304dacc5ed6d7e962c5df7c94b0a67e73f84783","5b5bb917a0f051395c425920f084fce2"), Insert("a4ca2cad4e5662c3bfdd38df5fc6dd158e125cbde07a4c549431b38da3a61c44","4440d1c4032329a4408f0d84baf4ae24"), Insert("fe95b3aad90f7be6345c7e3a321e3e4b211929bdaa0dfe3d5d37410f2ff2bfbf","5f7b9c94e7d96216779b2c360b9ef040"), Insert("41c55b11a7f61fd17ad228a98195383b5fc084bcc1689839bf4a8f858dbe5390","b356acb04eefe3687b2cd211a5989b21"), Insert("92982f135c505f4411116f8e6a3d6f4b05468cc175df63713adca98fbb2ca21e","4283e20470f9db447aa7e2ff4c75dd1f"), Insert("9f26be0d45df9f7d8193322a780823b6a42e39415f62ea8a431a3579c2d89890","59405deb9da456de5a2f6048052dcfe7"), Insert("08df47d9e21a228b56872d187e7ca0033dfe93fc3afa1d1f754d6a40a427524e","44063e6f03f96415569d6262775712f9"), Insert("58b5f141d5b0d4f4c991e8ebdc6e73b3fb661d6c4e29eed688b70850d37cff62","659387d105856c8859ec1d78e34a65e5"), Insert("bcaa68a3b5f6fc7ae09a5f4f3156db9d556a6e858811a2973f77eee881167b69","bb23952d560dace56e9bf3170b1f9090"), Insert("053d23c7067a430081b807b95b96ec914ecb974275785953236eddec3c78aa9c","678370b4aa1c70170c1228e344e0fe02"), Insert("d37aeeca4ad298dccf1885946c7ea3cc573342a357b7387c23cf4d7fa7103f3b","b79baf3104d094307c98ee33bfb23049"), Insert("d8795a288935436eee56b8af32504a76ac33895a827f190d69c0329285c1a4ef","9db3e32a35f3f082734da766fd76afe1"), Insert("fa99ea1df1e1ec49ede3ecf66c5a9473c0bd0603eceae251771c22bd2ba84566","3c77ace7964560d62915639d25b010a8"), Insert("aaa10a1f6442ab992e7b17818c72c50f3486b22a02dfc7edeb24ec93d13fc7c1","98f17e60d8c8cd7237906873e569d113"), Insert("e4d5a2975d563d0ee36b581aa024549fe3cdc7a5f682d037ff64b93f835aa495","7f5eb623237b593e291d6e74be684077"), Insert("3eef10eaab9e14d6329a74dde04575747e3b1b10e8f8413d1f474392d3952f88","863522e89cb49b3a3f3b60c517aa742e"), Insert("2dca8ddb1ffbb4e6d25aa9ac83edd73c7c47da9c2c671a3b4f79eb69bf0314ea","b8061cec7190062643ca3ec7c3bd03d9"), Insert("8c1fb9dbe4310f55128fb4bc8428957628757a42dde016a0bf15f59352eac8ed","9bd7b75c06b002762e10b9cb5869c005"), Insert("63f5e594f305b10bd6d4efa17c7fc64855aa75f4241451d2440e1890c21de5d1","be156e894cb55e0e36091ea96811841d"), Insert("dc021821a7b8c6c4149b1d6340c373c3d072b9eea3eb33b2a9a30ad8f0444c15","2716a7a3b6a28eab0718e8ee17dbec47"), Insert("a0e3dbe575c3d386c87edf9b038ad1dc85c16673a9f9822bda12c028d3c78d17","3b9381720dfe2b867428be45f0e8ab0f"), Insert("3fbbac896a6f6189f29f7440be817332de6f8d2d72f2d55d8c5f2d7a08d9ba4c","a859a79147a4fa1668034d261756e48a"), Insert("cd6050353dbfe56285929b17ef824565e1e6ee9776ef2e30719296e5638f1f83","096b363c35f8ae5376cae0e7a598b916"), Insert("3ee0e1bebd6f4a3b48e45a3036aa13bdf91915066af52ac082c128220072e559","d3f86ffb7237259e2c366789879c5dc2"), Insert("6a7fc569c17acdd915d057c5a3a474c2a46084dc5f44604ad4c0a6c10763eecd","8309468daa78abaa3342ecccef317808"), Insert("c64af22acee45a41ec9dad0c22663588437878c88bec56a31a3740f13e57a54c","92243f940c1d503e4cd55170117540f7"), Insert("62c53a6093e9f3dec35db79351227c1fddceea71954a1496ba1b8299f2d27b8b","cd0121eba771785f47417c877696dfe2"), Insert("15206aba0f8bf92e8ea9d4d9eb2db214c6086da88605180f090024183ca4ec21","b61777769af56cd0742fc2160c9336dd"), Insert("a8296d3733c1ac6981e1027908f5a4ee3839d0fa76ffc84a5e117fd4b3c1288c","11c6cc6080a083393873da0e37f41a5b"), Insert("fd73b884610f1ec81d000a957ba21facb57a8dcb136b8b9228072de31772d3d5","666d33ce07008ce10123f7ccef274629"), Insert("1ea6aac667fc1a99abbb04b45128d8b07b42928e399ec8a4822ab5978373fa14","9f4719db94e10cdf13b77f5ef3fe7d3a"), Insert("0362af1eaf3b25f71fb1db4775ae57264e5fc9f933faa3f5bb2012c95d8754cc","95b4775334f2d4120b6ea12e9d75c632"), Insert("f1cb97a2f42f497e2292f1faeee22996c4e5da3c02beb757417125338ed2d28b","e62b628a0d52477a16fb486f7a5ee886"), Insert("fe4938a1c6a505c8180f15907672eebc736014e795d6f92ae465848d92210615","55af2c2e1cf22737595f230b0edeee42"), Insert("6e9c564e1190f821aae7326dee8a31b16dd53216dd724011f21c09c0ac7909bc","84d7eea349dc6c676f5c05c70a6c66a0"), Insert("f139bc505fa76567197a197307cf668b3c8a858b40d3fd54d66099b9baa0fde4","25ac61e586c276561b28a34e9421e32a"), Insert("78ac97b232880841dc4d417274486f5db9e3cb5a84d44a94624ecf2e77d1eeea","caf7061b8cc30f08792ebbf4ee2333cf"), Insert("369b593ae971613636048143b39d895148aca2eed84f91bba2a03009f2e30c68","97d584cff7c21d040b1a10783998ff7b"), Insert("419b1c45fcb6080fe8d091474e71b413974e2848dd1c823c8e809fb1d71f0f23","d77a5e35a4455a3e2036fa9d4a45cf11"), Insert("75c98f00c72fd894663d0cbd7f25d6aa890d76e1091eebb0a2d888e7be20e054","8c23c50f92960f1a125313050812858f"), Insert("c1b74d2971a2a0d09896d7f903692c71c8bc6a1b745d3fc4e70065d4beed4b36","d2f84c70fa4d85245183efb8390e03a8"), Insert("48f974117ec1de3898f40dd7d1de774b17dfcc4f3f5b97caab8327a13b51e7e6","697ff127028aa8c3218abf370957f8f1"), Insert("336e172aabe748ba306f5527f7b0c808132a6b9bb5c8693aca8c6debdb638ed1","45038d28c5bafd4209a47003a9d64fa6"), Insert("47f54faf228c8c7a95a03223db943693d4a64cf0fc3fb45ea0f8daf18034ecbf","d30b3bfe4307ee2f4031a5fc836289d7"), Insert("5cb7a321448962d35dfbc168ffc5e372c07879592027571b6d4e6f15f257c871","68f672a7beaf3d2a131984679a6d9b16"), Insert("e0ccef093f197747577bfbe4688d06425976dc94c41aff62b4a02ce4cf201585","167320c01294b05a3ee0335d79e2f28b"), Insert("3e312123cc657dd53ad9ead5f7d883a199d3ab8fe1ea8f9bf31ab4c332c1d5d3","4759442ed6afee0a65f1121f0536dbea"), Insert("2f94e8d04f92deb67ec1cf40fd95111134498a239e860da64f42ac65cf9a4fa0","57a074f6e979e0684eca779377ac9c20"), Insert("4dd254290bb99e72cb8ef55c07328dd6e8c09da2460de02dfa20c57c990db64a","b7b82ec4ae2e7dd045ac127321d4d9c5"), Insert("a85ad9d6d5b02e425a36eeca897356dea45b0899218cd4fdc549871c060b7875","1a0ac99e765d076b31a71326d98a12fc"), Insert("2e36ffa9b0560fb5bd36fe3cc18be9fffab368ae97689db29162a5b25bb8defe","11ff39bf235e45f5754aa8e6304ccb30"), Insert("e0370a1237d4d3bd28386115122b12d3eda2b82545d9ada6ea8fdb999901db28","2e2b9d3f779a1a8740ccb5d02f9f8a42"), Insert("256098566aab2d640ccf672e7702031ade9b457ca9d77b968bc45d4ebe37f7a4","9abf1d8934da44465a586d4268f138ee"), Insert("75dd6e9655c2a170c6d86da6cc2f5f7560e3825cf18f50a12c11b25ef76b1027","02bd8d8320bde8c0146dadf4082f6cae"), Insert("19a1b37e6071f158794bd3f71f050f986dc2b20b5f7e2c73349a43ed2fc95632","a66fcb935a9a6e8901d4d19765b225c0"), Insert("325e4578fb95d9846b940ee082a9e2742e220ac7b2d2ad33fd22129ff852340d","fe1e86e1cd7d6fc5063f1c0dba350942"), Insert("432219d452dbf20bcb0580950de0e8d8f215d581eea13cfdf83a6c52abbc8cfb","5ace91de860e0bf653eedfe5604193fc"), Insert("63b426ea793d902b649d92a0e8101cc29bef28f129b04d41ead32d6571f6a86c","1a78cae401352839223dee36395a37e0"), Insert("2b75812d6b376bd8ee850e2a9ee9e62e9e183f665377cfc28e0d5a4132e23e78","5044374f9f47c2fe7e99cd02d78f19a4"), Insert("d1a913bb6ed0009717864aee5f3724ae1b76c0767e407807d2ca3a074bdb991e","8747502115327b0b63139c9362a1d232"), Insert("972af09a09ce7197e75c8f202d35e61fbeda2b5a80fa58ba95ae77dec094af9a","0d85cb63ad0fa9a350dcefe97b7db1b0"), Insert("df272eb60444fc1b9c14f52662b10c2c2aba8ca6761f83943c81dfcbd20a6636","d4f6dffc036582bd659cda3f25adb5f0"), Insert("4db1cd1ac6a4eb117d2837766727a33a7039e862fb5df7fe0c37dcd22798d0fd","5ce9de9b38f34a8a3b8f677274c7ccae"), Insert("26340a0aed14a459bd3c8b4f2e0092736701c35127d0bfc54fc04143a0f68f49","f4e2b49037db6ec11670e506bf2a4e54"), Insert("70340cdcad3993558b5da5d759a6f76579f30ce0ae0535758eb853848dfa8038","0a7c40d8bdef0ba542f6a502728ce005"), Insert("59009a7346956fbd5f65527b757b79dcd6ede5778cc1d36933e8f8813ebdae6c","5eeaab358a18c5947e098bcfc698adfc"), Insert("9373150388beb70d1cb486b453d765c4b882cd5e1fe8c4b0a1da71f8f2bcfffc","bab707b6ac8ca2774ad680b806ab0f9f"), Insert("28f68dcdb534e96094e28936cec858d939f0aa21cac2d5bab87fa61357d88196","964d3ac980d9dfbe3ef2ab1161a81a4f"), Insert("894c207c3f92fce8087000ff5242326968f0a2f2a07ca821258f6a639a92741b","b7300e02c9e0bf264b6f68d911b48aeb"), Insert("ee4248dd48eebbb06c50dfd8eb8cca90ebfe3a040727ec8e1cf47ba5d2d02dcd","ef2f86e52d43f5d843a232d296abf18c"), Insert("cb8800b5154e058866873b7c74fee454d7c22d7f22d2923b4d806cf662c200a8","7994640e21a4c147106719719cce5f7c"), Insert("05d00696414311d892e9ff87498d9e695ef22547462dba9baa62de1ec82f1752","e8a9507e195723a64e35fac71a3b9166"), Insert("0bed223a72824a24eccfe2adadca145cc6b80cb32330eef958cecaffe708f702","1c5f2e4fe7930d5d46c10c2ac57bbe05"), Insert("72b6c1b9d942955d5eab90af9346a90241adf0a2d7de88ab30ed43af5023d47f","944e0c961934e9881ebd8ab16cf8b2fc"), Insert("06d174e26a3db9d508bf25b5f18ae66fa9100227a71c66abab07c9e2ca304da4","fc0c861631a2528f7bc5f5b3c266d980"), Insert("7d0cd821342853406cbf929904a7ab8e214a8df41bec567f62a77f917b487852","5d9d21ea7d825bee3794c4a7c81b01a3"), Insert("79317254fb0c25b66f0586f813c1f6ff2164a640b25431f0519c59d2b96d68b0","6243711ebd9dd51a4a8f37f0f03d17a5"), Insert("4eee20ea80e093e87f31ea498803e5e32b5ef2576d8f41a78351cabf7322f27c","45864db9601a18a424ec79d202aa5360"), Insert("724e88691cca6046ff0f0d167b762127e5758672c35036ff0f8a42061ec3bb63","dbb0c5dd2e243f5c5398e1cad505feb0"), Insert("dc876e92edc9d2a9e8bbc6f072110a351513c941a45fe8bfb1097bf524676d78","c63d47cc5497830c289457426d4aedd9"), Insert("22e1daa558985ba30ce48214b086b3ad6401962599d52c2b5e8f8b134a8fa9d6","2006c91ea4f816f30c80667057f632ce"), Insert("d9861f7a59867d5156bf76566bcfc59300683eab8816211fc336538da94c53ee","c83fb6f85e44027c13cf79303e0eef43"), Insert("728c5a9605b43e0eab7c281fccd4d0a42579db51e57ed1543c880782a04aa30e","7f67517578f38cca4b96ff48f15dcbb7"), Insert("c64e79c1ccf52f8c8db2095381eac5a24a4693f2919a12bc51250133654d047a","36397422db755db07c8a7e0c2eed1797"), Insert("37341f63d44ad9772cabefd63d1c2f3b264897aaf9da51fa5ab539c4876f40fc","e71c006765fc0d0c5e577a1121270ba2"), Insert("c99fd09b8875c102d4374ae7ae258548b41a2377921ba593776385254282dd36","5b7cc052c2af1c5a46dc063b19f6b799"))
    in.foreach(m => prover.performOneOperation(m))
    prover.generateProof()

    val mods = List(Remove("5cb7a321448962d35dfbc168ffc5e372c07879592027571b6d4e6f15f257c871"), Remove("628181857476ed88dcbf0d77c460b8626cd968a9bdf43c1d2ea67f2acd3694d3"), Remove("62c53a6093e9f3dec35db79351227c1fddceea71954a1496ba1b8299f2d27b8b"), Remove("63b426ea793d902b649d92a0e8101cc29bef28f129b04d41ead32d6571f6a86c"), Remove("63f5e594f305b10bd6d4efa17c7fc64855aa75f4241451d2440e1890c21de5d1"), Remove("66566ba505b632ce2fe70973bd2f695f62ca61edf78dd855424e1b80ed9db7ef"), Insert("f95d8f8958dae7957313842290d6c985e49caf7d5de63085a4edde5b0bd002a9", "56e463c8f3614070131984679a6d9b16"), Insert("f4290c65a3fdc83c308a420a6a188df42c75ddeb97367458531e9cd820ff8cf6", "03b0c41bc7785b8e4149a49ebad3030a"), Insert("83c8710c320e5f83243219d034db074fecf07c216bad9720ddaba2c2a355cb0c", "a7b9d102dff1759147417c877696dfe2"), Insert("87ef0ce10ef152a7710f1d1ebaa900f127d2237780674a0ff1e927c69cc4957f", "752bf9c49718121e223dee36395a37e0"), Insert("116dadedf0b32272044aa6b4b4440c0e4f340af205ebec098e6c364b89483cae", "6b9dcebee140a24b36091ea96811841d"), Insert("20fd72b94b85362d4305d4e61e80d17ffdc809bb65c6282851e4af3ea26fb0f3", "fadbbf6d917c0048246c4461975e7fef"), Remove("59009a7346956fbd5f65527b757b79dcd6ede5778cc1d36933e8f8813ebdae6c"), Insert("6600fb2be8bf70ccb25c5f44b6a2f84c37a87143eb42a9dd55ebdebeb37fbc87", "ba4e81b0be31d1157e098bcfc698adfc"), Remove("4dd254290bb99e72cb8ef55c07328dd6e8c09da2460de02dfa20c57c990db64a"), Remove("4eee20ea80e093e87f31ea498803e5e32b5ef2576d8f41a78351cabf7322f27c"), Remove("58b5f141d5b0d4f4c991e8ebdc6e73b3fb661d6c4e29eed688b70850d37cff62"), Insert("1adfd8f4ebef7085d4e12e8bf5c1b0df2815b42a9fc17e524532367c6663b4a4", "12428bd3c6b90a3945ac127321d4d9c5"), Insert("5da1d13a2010533691b55e210e15f839c5336e975c55aa433537bbfa7d0788ea", "1ded810ead7d421f24ec79d202aa5360"), Insert("476588a50ef9f7e7fbe758b44892652590cdac93dc2cb3967deded935615a07f", "efa9215460672b9c59ec1d78e34a65e5"), Remove("4db1cd1ac6a4eb117d2837766727a33a7039e862fb5df7fe0c37dcd22798d0fd"), Insert("13bc02ec628797ae83b27496efcca59e6cba72d4dc25b903f43d643cea7e40b6", "8659eac173f419c93b8f677274c7ccae"), Remove("41c55b11a7f61fd17ad228a98195383b5fc084bcc1689839bf4a8f858dbe5390"), Remove("432219d452dbf20bcb0580950de0e8d8f215d581eea13cfdf83a6c52abbc8cfb"), Remove("47f54faf228c8c7a95a03223db943693d4a64cf0fc3fb45ea0f8daf18034ecbf"), Remove("48f974117ec1de3898f40dd7d1de774b17dfcc4f3f5b97caab8327a13b51e7e6"), Remove("4a83fefebe881f26974969c3127ebbfe711358cb89465bc3b186f895bcd61f5e"), Insert("4ffb34e639149a39ee373358ebd20a9d91b3f7436558cc7d93ea7a0faf8cace8", "ec04e5f73a7a30f87b2cd211a5989b21"), Insert("5cbb132d2e59bc2b4321e74b0f717cdd63139e987b192b050b9355da790cfec3", "7743706723e58fc553eedfe5604193fc"), Insert("81cdfba25942dc0b8a364f30099ccd89d6bcde41f0a48eb153a258ce43bad62d", "d417b1fa754c8a324031a5fc836289d7"), Insert("64f4e9275fdebd068bb14658481a6f1dd409225012a89dd27e9583b9d0c0038a", "d10f0f9cbedd3d2a218abf370957f8f1"), Insert("69151a884bf05b83b32856caad42268bbf783fb5678099178821fc84f49c076f", "4d699f2251f217a7318a65fc169060e5"), Remove("3fbbac896a6f6189f29f7440be817332de6f8d2d72f2d55d8c5f2d7a08d9ba4c"), Remove("419b1c45fcb6080fe8d091474e71b413974e2848dd1c823c8e809fb1d71f0f23"), Insert("aa000113afd1e3b12122a3fe583811d4b4c66de094d285f2e8abbfce9f49f859", "fed4138a9cdabf0168034d261756e48a"), Insert("a7b847359c4e049330b0b9050b83d4bc6776101502166c72aff9960347124bbf", "56412b52851444b92036fa9d4a45cf11"), Remove("325e4578fb95d9846b940ee082a9e2742e220ac7b2d2ad33fd22129ff852340d"), Remove("333724f1e5ed593ff3760e2fd14257e53320fcaba195198fe364c18317c8357a"), Remove("336e172aabe748ba306f5527f7b0c808132a6b9bb5c8693aca8c6debdb638ed1"), Remove("369b593ae971613636048143b39d895148aca2eed84f91bba2a03009f2e30c68"), Remove("37341f63d44ad9772cabefd63d1c2f3b264897aaf9da51fa5ab539c4876f40fc"), Remove("3e312123cc657dd53ad9ead5f7d883a199d3ab8fe1ea8f9bf31ab4c332c1d5d3"), Remove("3ee0e1bebd6f4a3b48e45a3036aa13bdf91915066af52ac082c128220072e559"), Remove("3eef10eaab9e14d6329a74dde04575747e3b1b10e8f8413d1f474392d3952f88"), Insert("8154445ab66a5061b7804f259b09e1625e9e9e7adc4543370951b134c02e1a7b", "ca854b7a9e1faf73063f1c0dba350942"), Insert("f30edcace9bb49125389432092246a0edb2f8de700118177fb2a22d7d0bd5a3f", "bf7608020c18def50f319a10a4166099"), Insert("24ac6ee3a6d66995b58f760fa17d9c832a48bc696797d641bff45faa345b1482", "ccb6d4ee8da9dcd209a47003a9d64fa6"), Insert("c233c237611314a789e6ef8665e6787a4506f2fabea785521bb1750affbe6034", "574abdccc173df1e0b1a10783998ff7b"), Insert("abf1638449815d210f44216133c411e05787359d25171e67496315ebf0705104", "3cb111384825599f5e577a1121270ba2"), Insert("f15b847f1e548dc27f27ce7a81c233b9d23f339323e33e053655605f63afd7f1", "5e61f0dbaf5215b165f1121f0536dbea"), Insert("cac6b8babc01acf6d16ce13c19127562b92af53e848f78aa9453d9ec6e399ebb", "22c1070a8f4c58ac2c366789879c5dc2"), Insert("0c081bc4860cd3dcfd184ab5cf95d8e84404b5baebeeb4369476d95d0ef17302", "342ff6039a7ebd5f3f3b60c517aa742e"), Remove("256098566aab2d640ccf672e7702031ade9b457ca9d77b968bc45d4ebe37f7a4"), Remove("26340a0aed14a459bd3c8b4f2e0092736701c35127d0bfc54fc04143a0f68f49"), Remove("28f68dcdb534e96094e28936cec858d939f0aa21cac2d5bab87fa61357d88196"), Remove("2b75812d6b376bd8ee850e2a9ee9e62e9e183f665377cfc28e0d5a4132e23e78"), Remove("2dca8ddb1ffbb4e6d25aa9ac83edd73c7c47da9c2c671a3b4f79eb69bf0314ea"), Remove("2e36ffa9b0560fb5bd36fe3cc18be9fffab368ae97689db29162a5b25bb8defe"), Remove("2f94e8d04f92deb67ec1cf40fd95111134498a239e860da64f42ac65cf9a4fa0"), Insert("c4daefc8c7d25e534009102b1b9e047fec3fd9a80d55953d171c0ef6d83cb968", "714b51fd89ed203b5a586d4268f138ee"), Insert("ffba8c2d4ffa8fe4648547ec98009f622c4e6a5cfec05bbf3c12f73a59378616", "25434341db41e9f51670e506bf2a4e54"), Insert("da4003be59ac3eeccb618c7bff6eff52ed577798976d878b85b8a898f6e30cb3", "8f3ef73098d91fa73ef2ab1161a81a4f"), Insert("50a14dfca657cf0021a9d232581f311290ae288c570121e0c70666ed55f8ee27", "1511e6de51c02ef57e99cd02d78f19a4"), Insert("0fc5fc67fb22aaab3ea5661374fd6a2a9f5d7214172ad43fc4f831245dcc72a8", "97950efca92a995243ca3ec7c3bd03d9"), Insert("e17f658e4fcea87f94b67999e18f8748ae13fc6b7fe7a8cd0b38cd525d24000e", "8fa4f6a6541cb846754aa8e6304ccb30"), Insert("fa56e0fcfae8b1949df48320fd8384f0e71594c10652c5b597396f92bff91f62", "b42088f81ab1efee4eca779377ac9c20"), Remove("06d174e26a3db9d508bf25b5f18ae66fa9100227a71c66abab07c9e2ca304da4"), Remove("08df47d9e21a228b56872d187e7ca0033dfe93fc3afa1d1f754d6a40a427524e"), Remove("0bed223a72824a24eccfe2adadca145cc6b80cb32330eef958cecaffe708f702"), Remove("0d58e0cda79b82eddf8d518d4a1addf5a92447091d78bcecdb727ab0c81d7a7b"), Remove("0f09f7704ed285c56154a2f7aef6eadde3e0faf9f3f07bb84393d7f83f8f9669"), Remove("15206aba0f8bf92e8ea9d4d9eb2db214c6086da88605180f090024183ca4ec21"), Remove("19a1b37e6071f158794bd3f71f050f986dc2b20b5f7e2c73349a43ed2fc95632"), Remove("1ea6aac667fc1a99abbb04b45128d8b07b42928e399ec8a4822ab5978373fa14"), Remove("22e1daa558985ba30ce48214b086b3ad6401962599d52c2b5e8f8b134a8fa9d6"), Insert("59682cb496608950676f8354c5a368fd1768ecc8cc54a8b68b70b356f1ab5392", "acc00000811dc0a97bc5f5b3c266d980"), Insert("8803c2a4a9db10cfa4334b7ea30446f13ab60ce455bb814b10727eea2ce64517", "b26fcd738f5a4050569d6262775712f9"), Insert("75b7a9253a527b4943eda377d71e5f97461ed021bb82c27c030f0dc2e11ee9c1", "78a239cf569ef80e46c10c2ac57bbe05"), Insert("089152570def1e5a7b3b895fdcc1596405c7d09ea0a6f30d9cfaa8069fcb52ea", "3d3c68ad26ecc5be64f81f3af4c73aea"), Insert("a6be39bfcb06978dcdc8ebdd382b29bfe2f533742542574ede57cc6fc862f17a", "0f3f8cbe7accc279779cf2eadb8854ea"), Insert("a5125cf7eef4f980c6dbcf2ca35fee7b44630994c54583b33c104c0819d8dabf", "033c37235161a21c742fc2160c9336dd"), Insert("8be351cecbe265ff8a8c0e92f0756963a08cc073647c3bba5e7a85c99208bfd9", "1b40e3f6098534f801d4d19765b225c0"), Insert("c146dc743368d717d0987322a5bfc6eeb26d591b15b2a87b864621ed3a4ec2a3", "40dc857488c7f0fa13b77f5ef3fe7d3a"), Insert("4013fbb3c15e12b172505bc4b8a03c47e95e9684d63c7b74a614e7a6bcd3140a", "d2f536410dbc95c60c80667057f632ce"), Remove("0362af1eaf3b25f71fb1db4775ae57264e5fc9f933faa3f5bb2012c95d8754cc"), Remove("053d23c7067a430081b807b95b96ec914ecb974275785953236eddec3c78aa9c"), Remove("05d00696414311d892e9ff87498d9e695ef22547462dba9baa62de1ec82f1752"), Insert("38f4a80b6061d8d5a719976a7ef4bb9a91abb1042f9a302291cd82de1e76e4f7", "cb704a7656ef281e0b6ea12e9d75c632"), Insert("415dd03a378ce730475cdbbe0c11c0065483cc73e3d0533cc6b95513d219be57", "f8884f7821d1122d0c1228e344e0fe02"), Insert("eca5bd7cdd5f27dd988910c17413180ed9dec5195b654fdb4f9627f432c80567", "4d681990c382c28b4e35fac71a3b9166"))
    mods.foreach(m => prover.performOneOperation(m).get)
    val toRemoveNodes = prover.removedNodes()
    prover.generateProof()
    toRemoveNodes.foreach { rn =>
      prover.contains(rn) shouldBe false
    }

  }

  property("removedNodes() should not contain new nodes") {
    def visitedNodes(node: ProverNodes[D]): Seq[ProverNodes[D]] = {
      if (node.isNew) {
        val pair = node
        node match {
          case n: InternalProverNode[D] =>
            val leftSubtree = visitedNodes(n.left)
            val rightSubtree = visitedNodes(n.right)
            pair +: (leftSubtree ++ rightSubtree)
          case _: ProverLeaf[D] => Seq(pair)
        }
      } else Seq()
    }

    val prover = generateProver()._1
    forAll(kvSeqGen) { kvSeq =>
      val mSize = kvSeq.length
      val toInsert = kvSeq.take(mSize).map(ti => Insert(ti._1, ti._2))
      val toRemove = (0 until mSize).flatMap(i => prover.randomWalk(new scala.util.Random(i))).map(kv => Remove(kv._1))
      val modifications = toInsert ++ toRemove
      modifications.foreach(ti => prover.performOneOperation(ti))
      val removed = prover.removedNodes()
      val newNodes = visitedNodes(prover.topNode)
      newNodes.foreach(nn => removed.find(r => r.label sameElements nn.label) shouldBe None)

      prover.generateProof()
    }

  }

  property("return removed leafs and internal nodes") {
    val prover = generateProver()._1
    forAll(kvSeqGen) { kvSeq =>
      val oldTop = prover.topNode
      val mSize = kvSeq.length
      val toInsert = kvSeq.take(mSize).map(ti => Insert(ti._1, ti._2))
      val toRemove = (0 until mSize).flatMap(i => prover.randomWalk(new scala.util.Random(i))).map(kv => Remove(kv._1))
      val modifications = toInsert ++ toRemove
      modifications.foreach(ti => prover.performOneOperation(ti))
      val removed = prover.removedNodes()
      removed.length should be > mSize
      toRemove.foreach(tr => removed.exists(_.key sameElements tr.key) shouldBe true)
      checkTree(prover, oldTop, removed)

      val modifyingProof = prover.generateProof()
      prover.removedNodes().isEmpty shouldBe true
    }
  }

  property("proof generation without tree modification special case") {
    val startTreeSize = 82
    val toRemoveSize = 1
    val (prover, elements) = generateProver(startTreeSize)

    val mods = elements.take(toRemoveSize).map(e => Remove(e._1))

    val (nonModifyingProof: SerializedAdProof, nonModifyingDigest) = prover.generateProofForOperations(mods).get

    mods.foreach(op => prover.performOneOperation(op).get)

    prover.removedNodes()

    val proofBytes = prover.generateProof()

    nonModifyingProof.length shouldEqual proofBytes.length
    nonModifyingProof shouldEqual proofBytes
  }

  property("proof generation without tree modification") {
    val prover = generateProver()._1
    forAll(kvSeqGen) { kvSeq =>
      val insertNum = Math.min(10, kvSeq.length)
      val toInsert = kvSeq.take(insertNum).map(ti => Insert(ti._1, ti._2))
      val toRemove = (0 until insertNum).flatMap(i => prover.randomWalk(new scala.util.Random(i))).map(kv => Remove(kv._1))
      val modifications = toInsert ++ toRemove
      val initialDigest = prover.digest

      // generate proof without tree modification
      val (nonModifyingProof, nonModifyingDigest) = prover.generateProofForOperations(modifications).get
      prover.digest shouldEqual initialDigest
      toInsert.foreach(ti => prover.unauthenticatedLookup(ti.key) shouldBe None)
      toRemove.foreach(ti => prover.unauthenticatedLookup(ti.key).isDefined shouldBe true)
      val verifier = new BatchAVLVerifier[D, HF](initialDigest, nonModifyingProof, KL, None)
      modifications foreach (m => verifier.performOneOperation(m).get)
      verifier.digest.get shouldEqual nonModifyingDigest

      // modify tree and generate proof
      modifications.foreach(ti => prover.performOneOperation(ti))
      prover.removedNodes()
      val modifyingProof = prover.generateProof()
      prover.digest shouldEqual verifier.digest.get
      Base58.encode(prover.digest) should not be Base58.encode(initialDigest)
      modifyingProof shouldEqual nonModifyingProof
      toInsert.foreach(ti => prover.unauthenticatedLookup(ti.key) shouldBe Some(ti.value))
      toRemove.foreach(ti => prover.unauthenticatedLookup(ti.key) shouldBe None)
    }
  }

  property("randomWalk") {
    val prover = generateProver()._1

    forAll { (seed: Long) =>
      val e1 = prover.randomWalk(new scala.util.Random(seed))
      val e2 = prover.randomWalk(new scala.util.Random(seed))
      e1.map(_._1) shouldEqual e2.map(_._1)
      e1.map(_._2) shouldEqual e2.map(_._2)
    }
  }

  property("unauthenticatedLookup") {
    val p = new BatchAVLProver[Digest32, HF](keyLength = 8, valueLengthOpt = None)

    p.performOneOperation(Insert(ADKey @@ Longs.toByteArray(1.toLong), ADValue @@ Array.fill(4)(0: Byte)))
    p.performOneOperation(Insert(ADKey @@ Longs.toByteArray(2.toLong), ADValue @@ Array.fill(5)(0: Byte)))
    p.performOneOperation(Insert(ADKey @@ Longs.toByteArray(3.toLong), ADValue @@ Array.fill(6)(0: Byte)))
    p.performOneOperation(Insert(ADKey @@ Longs.toByteArray(4.toLong), ADValue @@ Array.fill(7)(0: Byte)))
    p.performOneOperation(Insert(ADKey @@ Longs.toByteArray(5.toLong), ADValue @@ Array.fill(8)(0: Byte)))
    p.performOneOperation(Insert(ADKey @@ Longs.toByteArray(6.toLong), ADValue @@ Array.fill(9)(0: Byte)))


    p.unauthenticatedLookup(ADKey @@ Longs.toByteArray(0.toLong)) shouldBe None
    p.unauthenticatedLookup(ADKey @@ Longs.toByteArray(1.toLong)).get.length shouldBe 4
    p.unauthenticatedLookup(ADKey @@ Longs.toByteArray(2.toLong)).get.length shouldBe 5
    p.unauthenticatedLookup(ADKey @@ Longs.toByteArray(3.toLong)).get.length shouldBe 6
    p.unauthenticatedLookup(ADKey @@ Longs.toByteArray(4.toLong)).get.length shouldBe 7
    p.unauthenticatedLookup(ADKey @@ Longs.toByteArray(5.toLong)).get.length shouldBe 8
    p.unauthenticatedLookup(ADKey @@ Longs.toByteArray(6.toLong)).get.length shouldBe 9
    p.unauthenticatedLookup(ADKey @@ Longs.toByteArray(7.toLong)) shouldBe None
  }

  property("BatchAVLVerifier: extractNodes and extractFirstNode") {
    val prover = new BatchAVLProver[D, HF](KL, None)
    val digest = prover.digest
    val keyValues = (0 until InitialTreeSize) map { i =>
      val aValue = Blake2b256(i.toString.getBytes("UTF-8"))
      (ADKey @@ aValue.take(KL), ADValue @@@ aValue)
    }
    keyValues.foreach(kv => prover.performOneOperation(Insert(kv._1, kv._2)))

    val pf = prover.generateProof()

    val verifier = new BatchAVLVerifier[D, HF](digest, pf, KL, None)
    val infinityLeaf: VerifierNodes[D] = verifier.extractFirstNode {
      case _: VerifierLeaf[D] => true
      case _ => false
    }.get
    val nonInfiniteLeaf: VerifierNodes[D] => Boolean = {
      case l: VerifierLeaf[D] => !(l.label sameElements infinityLeaf.label)
      case _ => false
    }

    (0 until InitialTreeSize) foreach { i =>
      val aValue = Blake2b256(i.toString.getBytes("UTF-8"))
      verifier.performOneOperation(Insert(ADKey @@ aValue.take(KL), ADValue @@@ aValue))
    }
    //extract all leafs
    val allLeafs = verifier.extractNodes(nonInfiniteLeaf)
    allLeafs.get.length shouldBe InitialTreeSize
    //First extracted leaf should be smallest
    val ordering: (Array[Byte], Array[Byte]) => Boolean = (a, b) => ByteArray.compare(a, b) > 0
    val smallestKey = keyValues.map(_._1).sortWith(ordering).last
    val minLeaf = verifier.extractFirstNode(nonInfiniteLeaf).get.asInstanceOf[VerifierLeaf[D]]
    minLeaf.key shouldEqual smallestKey
  }

  property("BatchAVLVerifier: extractFirstNode") {
    val prover = new BatchAVLProver[D, HF](KL, None)
    val digest = prover.digest
    val keyValues = (0 until InitialTreeSize) map { i =>
      val aValue = Blake2b256(i.toString.getBytes("UTF-8"))
      (ADKey @@ aValue.take(KL), ADValue @@@ aValue)
    }
    keyValues.foreach(kv => prover.performOneOperation(Insert(kv._1, kv._2)))

    val pf = prover.generateProof()

    val verifier = new BatchAVLVerifier[D, HF](digest, pf, KL, None)
    val infinityLeaf: VerifierNodes[D] = verifier.extractFirstNode {
      case _: VerifierLeaf[D] => true
      case _ => false
    }.get
    val nonInfiniteLeaf: VerifierNodes[D] => Boolean = {
      case l: VerifierLeaf[D] => !(l.label sameElements infinityLeaf.label)
      case _ => false
    }

    keyValues.foreach(kv => verifier.performOneOperation(Insert(kv._1, kv._2)))

    //First extracted leaf should be smallest
    val ordering: (Array[Byte], Array[Byte]) => Boolean = (a, b) => ByteArray.compare(a, b) > 0
    val smallestKey = keyValues.map(_._1).sortWith(ordering).last
    val minLeaf = verifier.extractFirstNode(nonInfiniteLeaf).get.asInstanceOf[VerifierLeaf[D]]
    minLeaf.key shouldEqual smallestKey

    //Test every leaf is extractable by key
    keyValues.foreach { kv =>
      val node = verifier.extractFirstNode {
        case l: VerifierLeaf[D] => l.key sameElements kv._1
        case _ => false
      }.get.asInstanceOf[VerifierLeaf[D]]
      node.key shouldEqual kv._1
      node.value shouldEqual kv._2
    }

    //False predicate make it return None
    verifier.extractFirstNode(_ => false) shouldBe None
  }

  property("Batch of lookups") {
    //prepare tree
    val prover = generateProver()._1
    val digest = prover.digest

    forAll(smallInt) { (numberOfLookups: Int) =>
      val currentMods = (0 until numberOfLookups).map(_ => randomKey(KL)).map(k => Lookup(k))

      currentMods foreach (m => prover.performOneOperation(m))
      val pf = prover.generateProof()

      val verifier = new BatchAVLVerifier[D, HF](digest, pf, KL, None)
      currentMods foreach (m => verifier.performOneOperation(m).get)
      prover.digest shouldEqual verifier.digest.get
    }
    prover.checkTree(true)
  }

  property("Tree without fixed value length") {
    val prover = new BatchAVLProver[D, HF](KL, None)
    var digest = prover.digest

    forAll { (valueLength: Short) =>
      whenever(valueLength >= 0) {
        val aKey = Random.randomBytes(KL)
        val aValue = Random.randomBytes(valueLength)
        val currentMods = Seq(Insert(ADKey @@ aKey, ADValue @@ aValue))

        currentMods foreach (m => prover.performOneOperation(m))
        val pf = prover.generateProof()

        val verifier = new BatchAVLVerifier[D, HF](digest, pf, KL, None)
        currentMods foreach (m => verifier.performOneOperation(m))
        digest = verifier.digest.get

        prover.digest shouldEqual digest
      }
    }
    prover.checkTree(true)
  }

  property("Modifications for different key and value length") {
    Try {
      forAll { (aKey: Array[Byte], aValue: Array[Byte]) =>
        val KL = aKey.length
        val VL = aValue.length
        whenever(KL > 0 && VL > 0 && !aKey.forall(_ equals (-1: Byte)) && !aKey.forall(_ equals (0: Byte))) {
          val prover = new BatchAVLProver[D, HF](KL, Some(VL))
          val m = Insert(ADKey @@ aKey, ADValue @@ aValue)

          val digest = prover.digest
          prover.performOneOperation(m)
          val pf = prover.generateProof()
          prover.digest

          val verifier = new BatchAVLVerifier[D, HF](digest, pf, KL, Some(VL))
          verifier.performOneOperation(m)
          if (verifier.digest.isEmpty) {
            println("problematic key: " + aKey.mkString("-"))
            println("problematic value: " + Base58.encode(aValue))
          }
          verifier.digest.isDefined shouldBe true
          prover.digest shouldEqual verifier.digest.get

          val lookup = Lookup(ADKey @@ aKey)
          prover.performOneOperation(lookup)
          val pr = prover.generateProof()
          val vr = new BatchAVLVerifier[D, HF](prover.digest, pr, KL, Some(VL))
          vr.performOneOperation(lookup).get.get shouldEqual aValue

          val nonExistinglookup = Lookup(randomKey(KL))
          prover.performOneOperation(nonExistinglookup)
          val pr2 = prover.generateProof()
          val vr2 = new BatchAVLVerifier[D, HF](prover.digest, pr2, KL, Some(VL))
          vr2.performOneOperation(nonExistinglookup).get shouldBe None
        }
      }
    }.recoverWith {
      case e =>
        e.printStackTrace()
        Failure(e)
    }.get
  }

  property("Lookups") {
    val prover = new BatchAVLProver[D, HF](KL, Some(VL))
    forAll(kvSeqGen) { kvSeq =>
      val insertNum = Math.min(3, kvSeq.length)
      val toInsert = kvSeq.take(insertNum)
      toInsert.foreach { ti =>
        prover.performOneOperation(Insert(ti._1, ti._2))
      }
      prover.generateProof()
      val lookups = kvSeq.map(kv => Lookup(kv._1))

      lookups.foreach(l => prover.performOneOperation(l))
      val pr = prover.generateProof()

      val vr = new BatchAVLVerifier[D, HF](prover.digest, pr, KL, Some(VL))
      kvSeq.foreach { kv =>
        vr.performOneOperation(Lookup(kv._1)).get match {
          case Some(v) =>
            toInsert.find(_._1 sameElements kv._1).get._2 shouldEqual v
          case None =>
            toInsert.exists(_._1 sameElements kv._1) shouldBe false
        }
      }
    }
  }


  property("Usage as authenticated set") {
    val SetVL = Some(0)
    val prover = new BatchAVLProver[D, HF](KL, SetVL)
    var digest = prover.digest
    //    val valueToInsert:Array[Byte] = Array.fill(SetVL)(0.toByte)
    val valueToInsert: Array[Byte] = Array.empty

    forAll(kvGen) { case (aKey, _) =>
      whenever(prover.unauthenticatedLookup(aKey).isEmpty) {
        val m = Insert(aKey, ADValue @@ valueToInsert)
        prover.performOneOperation(m)
        val pf = prover.generateProof()
        prover.digest

        val verifier = new BatchAVLVerifier[D, HF](digest, pf, KL, SetVL)
        verifier.performOneOperation(m)
        digest = verifier.digest.get
        prover.digest shouldEqual digest
      }
    }

  }

  property("Long updates") {
    val prover = new BatchAVLProver[D, HF](KL, Some(VL))
    var digest = prover.digest

    forAll(kvGen) { case (aKey, aValue) =>
      val oldValue: Long = prover.unauthenticatedLookup(aKey).map(Longs.fromByteArray).getOrElse(0L)
      val delta = Math.abs(Longs.fromByteArray(aValue))
      whenever(Try(Math.addExact(oldValue, delta)).isSuccess) {

        val m = UpdateLongBy(aKey, delta)

        prover.performOneOperation(m).get.getOrElse(0L) shouldBe oldValue
        val pf = prover.generateProof()

        val verifier = new BatchAVLVerifier[D, HF](digest, pf, KL, Some(VL))
        verifier.performOneOperation(m)
        digest = verifier.digest.get
        prover.digest shouldEqual digest
        prover.unauthenticatedLookup(aKey) match {
          case Some(v) => require(delta + oldValue == Longs.fromByteArray(v))
          case None => require(delta + oldValue == 0)
        }
      }
    }
    prover.checkTree(true)
  }


  property("zero-mods verification on empty tree") {
    val p = new BatchAVLProver[D, HF](KL, Some(VL))
    p.checkTree()
    val digest = p.digest
    val pf = p.generateProof()
    p.checkTree(true)
    val v = new BatchAVLVerifier[D, HF](digest, pf, KL, Some(VL), Some(0), Some(0))
    v.digest match {
      case Some(d) =>
        require(d sameElements digest, "wrong digest for zero-mods")
      case None =>
        throw new Error("zero-mods verification failed to construct tree")
    }
  }

  property("conversion to byte and back") {
    // There is no way to test this without building a tree with at least 2^88 leaves,
    // so we resort to a very basic test
    val p = new BatchAVLProver[D, HF](KL, Some(VL))
    val digest = p.digest
    for (i <- 0 to 255) {
      digest(digest.length - 1) = i.toByte
      val rootNodeHeight: Int = digest.last & 0xff
      rootNodeHeight shouldBe i
    }
  }


  property("various verifier fails") {
    val p = new BatchAVLProver[D, HF](KL, Some(VL))

    p.checkTree()
    for (i <- 0 until 1000) {
      require(p.performOneOperation(Insert(randomKey(KL), randomValue(VL))).isSuccess, "failed to insert")
      p.checkTree()
    }
    p.generateProof()

    var digest = p.digest
    for (i <- 0 until 50)
      require(p.performOneOperation(Insert(randomKey(KL), randomValue(VL))).isSuccess, "failed to insert")

    var pf = p.generateProof()

    // see if the proof for 50 mods will be allowed when we permit only 2
    var v = new BatchAVLVerifier[D, HF](digest, pf, KL, Some(VL), Some(2), Some(0))
    require(v.digest.isEmpty, "Failed to reject too long a proof")

    // see if wrong digest will be allowed
    v = new BatchAVLVerifier[D, HF](ADDigest @@ Random.randomBytes(KL), pf, KL, Some(VL), Some(50), Some(0))
    require(v.digest.isEmpty, "Failed to reject wrong digest")

    for (i <- 0 until 10) {
      digest = p.digest
      for (i <- 0 until 8)
        require(p.performOneOperation(Insert(randomKey(KL), randomValue(8))).isSuccess, "failed to insert")

      v = new BatchAVLVerifier[D, HF](digest, p.generateProof(), KL, Some(VL), Some(8), Some(0))
      require(v.digest.nonEmpty, "verification failed to construct tree")
      // Try 5 inserts that do not match -- with overwhelming probability one of them will go to a leaf
      // that is not in the conveyed tree, and verifier will complain
      for (i <- 0 until 5)
        v.performOneOperation(Insert(randomKey(KL), randomValue(8)))
      require(v.digest.isEmpty, "verification succeeded when it should have failed, because of a missing leaf")

      digest = p.digest
      val key = randomKey(KL)
      p.performOneOperation(Insert(ADKey @@@ key, randomValue(8)))
      pf = p.generateProof()
      p.checkTree()

      // Change the direction of the proof and make sure verifier fails
      pf(pf.length - 1) = (~pf(pf.length - 1)).toByte
      v = new BatchAVLVerifier[D, HF](digest, pf, KL, Some(VL), Some(1), Some(0))
      require(v.digest.nonEmpty, "verification failed to construct tree")
      v.performOneOperation(Insert(key, randomValue(8)))
      require(v.digest.isEmpty, "verification succeeded when it should have failed, because of the wrong direction")

      // Change the key by a large amount -- verification should fail with overwhelming probability
      // because there are 1000 keys in the tree
      // First, change the proof back to be correct
      pf(pf.length - 1) = (~pf(pf.length - 1)).toByte
      val oldKey = key(0)
      key(0) = (key(0) ^ (1 << 7)).toByte
      v = new BatchAVLVerifier[D, HF](digest, pf, KL, Some(VL), Some(1), Some(0))
      require(v.digest.nonEmpty, "verification failed to construct tree")
      v.performOneOperation(Insert(key, randomValue(8)))
      require(v.digest.isEmpty, "verification succeeded when it should have failed because of the wrong key")
      // put the key back the way it should be, because otherwise it's messed up in the prover tree
      key(0) = (key(0) ^ (1 << 7)).toByte
    }
  }

  property("remove single random element from a large set") {

    val minSetSize = 10000
    val maxSetSize = 100000

    forAll(Gen.choose(minSetSize, maxSetSize), Arbitrary.arbBool.arbitrary) { case (cnt, generateProof) =>
      whenever(cnt > minSetSize) {
        var keys = IndexedSeq[ADKey]()
        val prover = new BatchAVLProver[D, HF](KL, Some(VL))

        (1 to cnt) foreach { _ =>
          val key: ADKey = randomKey(KL)
          val value = randomValue(VL)

          keys = key +: keys

          prover.performOneOperation(Insert(key, value)).isSuccess shouldBe true
          prover.unauthenticatedLookup(key).isDefined shouldBe true
        }

        if (generateProof) prover.generateProof()

        val keyPosition = scala.util.Random.nextInt(keys.length)
        val rndKey = keys(keyPosition)

        prover.unauthenticatedLookup(rndKey).isDefined shouldBe true
        val removalResult = prover.performOneOperation(Remove(rndKey))
        removalResult.isSuccess shouldBe true

        if (keyPosition > 0) {
          prover.performOneOperation(Remove(keys.head)).isSuccess shouldBe true
        }

        keys = keys.tail.filterNot(_.sameElements(rndKey))

        val shuffledKeys = scala.util.Random.shuffle(keys)
        shuffledKeys.foreach { k =>
          prover.performOneOperation(Remove(k)).isSuccess shouldBe true
        }
      }
    }
  }

  property("successful modifications") {
    val p = new BatchAVLProver[D, HF](KL, Some(VL))

    val numMods = 5000

    val deletedKeys = new scala.collection.mutable.ArrayBuffer[ADKey]

    val keysAndVals = new scala.collection.mutable.ArrayBuffer[(ADKey, ADValue)]

    var i = 0
    var numInserts = 0
    var numModifies = 0
    var numDeletes = 0
    var numNonDeletes = 0
    var numFailures = 0

    while (i < numMods) {
      val digest = p.digest
      val n = randomInt(100)
      val j = i + n
      var numCurrentDeletes = 0
      val currentMods = new scala.collection.mutable.ArrayBuffer[Operation](n)
      while (i < j) {
        if (keysAndVals.isEmpty || randomInt(2) == 0) {
          // with prob .5 insert a new one, with prob .5 update or delete an existing one
          if (keysAndVals.nonEmpty && randomInt(10) == 0) {
            // with probability 1/10 cause a fail by inserting already existing
            val j = Random.randomBytes(3)
            val index = randomInt(keysAndVals.size)
            val key = keysAndVals(index)._1
            require(p.performOneOperation(Insert(key, randomValue(VL))).isFailure, "prover succeeded on inserting a value that's already in tree")
            p.checkTree()
            require(p.unauthenticatedLookup(key).get sameElements keysAndVals(index)._2, "value changed after duplicate insert") // check insert didn't do damage
            numFailures += 1
          }
          else {
            val key = randomKey(KL)
            val newVal = randomValue(VL)
            keysAndVals += ((key, newVal))
            val mod = Insert(key, newVal)
            currentMods += mod
            require(p.performOneOperation(mod).isSuccess, "prover failed to insert")
            p.checkTree()
            require(p.unauthenticatedLookup(key).get sameElements newVal, "inserted key is missing") // check insert
            numInserts += 1
          }
        }
        else {
          // with probability .25 update, with .25 delete
          if (randomInt(2) == 0) {
            // update
            if (randomInt(10) == 0) {
              // with probability 1/10 cause a fail by modifying a non-existing key
              val key = randomKey(KL)
              require(p.performOneOperation(Update(key, randomValue(8))).isFailure, "prover updated a nonexistent value")
              p.checkTree()
              require(p.unauthenticatedLookup(key).isEmpty, "a nonexistent value appeared after an update") // check update didn't do damage
              numFailures += 1
            }
            else {
              val index = randomInt(keysAndVals.size)
              val key = keysAndVals(index)._1
              val newVal = randomValue(8)
              val mod = Update(key, newVal)
              currentMods += mod
              p.performOneOperation(mod).get
              keysAndVals(index) = (key, newVal)
              require(p.unauthenticatedLookup(key).get sameElements newVal, "wrong value after update") // check update
              numModifies += 1
            }
          } else {
            // delete
            if (randomInt(10) == 0) {
              // with probability 1/10 remove a non-existing one but without failure -- shouldn't change the tree
              val key = randomKey(KL)
              val mod = RemoveIfExists(key)
              val d = p.digest
              currentMods += mod
              require(p.performOneOperation(mod).isSuccess, "prover failed when it should have done nothing")
              require(d sameElements p.digest, "Tree changed when it shouldn't have")
              p.checkTree()
              numNonDeletes += 1
            }
            else {
              // remove an existing key
              val index = randomInt(keysAndVals.size)
              val key = keysAndVals(index)._1
              val mod = Remove(key)
              val oldVal = keysAndVals(index)._2
              currentMods += mod
              require(p.performOneOperation(mod).isSuccess, "failed ot delete")
              keysAndVals -= ((key, oldVal))
              deletedKeys += key
              require(p.unauthenticatedLookup(key).isEmpty, "deleted key still in tree") // check delete
              numDeletes += 1
              numCurrentDeletes += 1
            }
          }
        }
        i += 1
      }

      val pf = p.generateProof()
      p.checkTree(true)

      val v = new BatchAVLVerifier[D, HF](digest, pf, KL, Some(VL), Some(n), Some(numCurrentDeletes))
      v.digest match {
        case None =>
          throw new Error("Verification failed to construct the tree")
        case Some(d) =>
          require(d sameElements digest, "Built tree with wrong digest") // Tree built successfully
      }

      currentMods foreach (m => v.performOneOperation(m))
      v.digest match {
        case None =>
          throw new Error("Verification failed")
        case Some(d) =>
          require(d sameElements p.digest, "Tree has wrong digest after verification")
      }
    }

    // Check that all the inserts, deletes, and updates we did actually stayed
    deletedKeys foreach (k => require(p.unauthenticatedLookup(k).isEmpty, "Key that was deleted is still in the tree"))
    keysAndVals foreach (pair => require(p.unauthenticatedLookup(pair._1).get sameElements pair._2, "Key has wrong value"))
  }

  property("Persistence AVL batch prover") {
    val storage = new VersionedAVLStorageMock[D]
    val p = new BatchAVLProver[D, HF](KL, Some(VL))
    val prover = PersistentBatchAVLProver.create[D, HF](p, storage, paranoidChecks = true).get
    var digest = prover.digest

    forAll(kvGen) { case (aKey, aValue) =>
      val m = Insert(aKey, aValue)
      prover.performOneOperation(m)
      val pf = prover.generateProofAndUpdateStorage()

      val verifier = new BatchAVLVerifier[D, HF](digest, pf, KL, Some(VL))
      verifier.digest.get
      verifier.performOneOperation(m)

      prover.digest should not equal digest
      prover.digest shouldEqual verifier.digest.get

      prover.rollback(digest).isSuccess shouldBe true
      prover.digest shouldEqual digest
      prover.performOneOperation(m)
      prover.generateProofAndUpdateStorage()
      digest = prover.digest
    }

    val prover2 = PersistentBatchAVLProver.create(new BatchAVLProver[D, HF](KL, Some(VL)), storage, paranoidChecks = true).get
    prover2.digest shouldEqual prover.digest
  }

  property("Updates with and without batching should lead to the same tree") {
    val tree = new AVLTree(KL)
    var digest = tree.rootHash()
    val oldProver = new LegacyProver(tree)
    val newProver = new BatchAVLProver[D, HF](KL, Some(VL))
    require(newProver.digest startsWith oldProver.rootHash)
    require(newProver.digest.length == oldProver.rootHash.length + 1)

    forAll(kvGen) { case (aKey, aValue) =>
      val currentMods = Seq(Insert(aKey, aValue))
      oldProver.applyBatchSimple(currentMods) match {
        case bss: BatchSuccessSimple =>
          new LegacyVerifier(digest).verifyBatchSimple(currentMods, bss) shouldBe true
        case bf: BatchFailure => throw bf.error
      }

      currentMods foreach (m => newProver.performOneOperation(m))
      val pf = newProver.generateProof()

      digest = oldProver.rootHash
      require(newProver.digest startsWith digest)
      require(newProver.digest.length == oldProver.rootHash.length + 1)
    }
    newProver.checkTree(true)
  }

  property("Verifier should calculate the same digest") {
    val prover = new BatchAVLProver[D, HF](KL, Some(VL))
    var digest = prover.digest

    forAll(kvGen) { case (aKey, aValue) =>
      val currentMods = Seq(Insert(aKey, aValue))

      currentMods foreach (m => prover.performOneOperation(m))
      val pf = prover.generateProof()

      val verifier = new BatchAVLVerifier[D, HF](digest, pf, KL, Some(VL))
      currentMods foreach (m => verifier.performOneOperation(m))
      digest = verifier.digest.get

      prover.digest shouldEqual digest
    }
    prover.checkTree(true)
  }


  lazy val kvGen: Gen[(ADKey, ADValue)] = for {
    key <- Gen.listOfN(KL, Arbitrary.arbitrary[Byte]).map(_.toArray) suchThat
      (k => !(k sameElements Array.fill(KL)(-1: Byte)) && !(k sameElements Array.fill(KL)(0: Byte)) && k.length == KL)
    value <- Gen.listOfN(VL, Arbitrary.arbitrary[Byte]).map(_.toArray)
  } yield (ADKey @@ key, ADValue @@ value)

  lazy val kvSeqGen: Gen[Seq[(ADKey, ADValue)]] = Gen.nonEmptyListOf(kvGen)

}
