package scorex.crypto.authds.skiplist

import org.scalatest.prop.GeneratorDrivenPropertyChecks
import org.scalatest.{Matchers, PropSpec}
import scorex.crypto.authds.storage.MvStoreBlobBlobStorage
import scorex.crypto.hash.{Blake2b256, CommutativeHash}

class SLNodeSpecification extends PropSpec with GeneratorDrivenPropertyChecks with Matchers with SLGenerators {

  implicit val storage = new MvStoreBlobBlobStorage(None)
  implicit val hf: CommutativeHash[Blake2b256.type] = new CommutativeHash(Blake2b256)

  property("SLNode serialization") {
    forAll(slnodeGenerator) { sn: SLNode =>
      SLNode.parseBytes(sn.bytes).isSuccess shouldBe true
    }
  }

  property("SLNode top node serialization") {
    val topRight: SLNode = SLNode(MaxSLElement, None, None, 0, isTower = true)
    val topNode: SLNode = SLNode(MinSLElement, Some(topRight.nodeKey), None, 0, isTower = true)
    saveNode(topRight)
    saveNode(topNode, isTop = true)
    SLNode.parseBytes(topNode.bytes).isSuccess shouldBe true
  }


  private def saveNode(node: SLNode, isTop: Boolean = false): Unit = {
    node.recomputeHash
    storage.set(node.nodeKey, node.bytes)
    storage.commit()
  }
}
