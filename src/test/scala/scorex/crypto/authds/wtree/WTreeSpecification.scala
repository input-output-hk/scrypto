package scorex.crypto.authds.wtree

import com.google.common.primitives.Longs
import org.scalatest.prop.GeneratorDrivenPropertyChecks
import org.scalatest.{Matchers, PropSpec}
import scorex.crypto.TestingCommons


class WTreeSpecification extends PropSpec with GeneratorDrivenPropertyChecks with Matchers with TestingCommons {


  def validKey(key: WTKey): Boolean = key.length > 1 && key.length < MaxKeySize

  property("WTree stream") {
    val wt = new WTree()
    var digest = wt.rootHash()
    forAll { (key: Array[Byte], value: Array[Byte]) =>
      whenever(validKey(key) && value.nonEmpty) {
        digest shouldEqual wt.rootHash()
        val proof: WTModifyProof = wt.modify(key, append(value))
        digest = proof.verify(digest, append(value)).get
      }
    }
  }

  property("WTree insert") {
    val wt = new WTree()
    forAll { (key: Array[Byte], value: Array[Byte], wrongValue: Array[Byte]) =>
      whenever(validKey(key) && value.nonEmpty) {
        val digest = wt.rootHash()
        val proof: WTModifyProof = wt.modify(key, rewrite(value))
        proof.verify(digest, rewrite(value)).isDefined shouldBe true
//        TODO Fix!!
//        proof.verify(digest, rewrite(wrongValue)) shouldBe None
      }
    }
  }

  property("WTree update") {
    val wt = new WTree()
    forAll { (key: Array[Byte], value: Array[Byte], value2: Array[Byte]) =>
      whenever(validKey(key) && !(value sameElements value2)) {
        val digest = wt.rootHash()
        val proof: WTModifyProof = wt.modify(key, append(value))
        proof.verify(digest, append(value)).isDefined shouldBe true
//        TODO Fix!!
//        proof.verify(digest, append(value2)) shouldBe None

        val updateProof = wt.modify(key, append(value2))
        proof.verify(digest, append(value2)).isDefined shouldBe true
//        TODO Fix!!
//        proof.verify(digest, append(value)) shouldBe None
      }
    }
  }

  def rewrite(value: WTValue): UpdateFunction = { oldOpt: Option[WTValue] => value }

  def append(value: WTValue): UpdateFunction = { oldOpt: Option[WTValue] => oldOpt.map(_ ++ value).getOrElse(value)}

  def transactionUpdate(amount: Long): Option[WTValue] => WTValue = (old: Option[WTValue]) =>
    Longs.toByteArray(old.map(v => Longs.fromByteArray(v) + amount).getOrElse(amount))

}
