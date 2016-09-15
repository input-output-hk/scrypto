package scorex.crypto.authds.wtree

import org.scalatest.prop.GeneratorDrivenPropertyChecks
import org.scalatest.{Matchers, PropSpec}
import scorex.crypto.TestingCommons


class WTreeSpecification extends PropSpec with GeneratorDrivenPropertyChecks with Matchers with TestingCommons {


  property("WTree insert") {
    //    forAll { (key: Array[Byte], value: Array[Byte]) =>
    //      whenever(key.nonEmpty && value.nonEmpty) {
    val key = Array(-19: Byte)
    val value = Array(-128: Byte)
    val wt = new WTree()
    val digest = wt.rootHash()
    val proof: WTModifyProof = wt.modify(key, rewrite(value))
    proof.verify(digest, rewrite(value)).isDefined shouldBe true
    //      }
    //    }
  }

  def rewrite(value: WTValue): UpdateFunction = { oldOpt: Option[WTValue] => value }

}
