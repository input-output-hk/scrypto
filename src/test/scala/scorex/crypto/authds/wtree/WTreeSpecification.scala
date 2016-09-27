package scorex.crypto.authds.wtree

import com.google.common.primitives.Longs
import org.scalatest.prop.GeneratorDrivenPropertyChecks
import org.scalatest.{Matchers, PropSpec}
import scorex.crypto.TestingCommons
import scorex.crypto.authds.Level
import scorex.crypto.hash.Blake2b256Unsafe


class WTreeSpecification extends PropSpec with GeneratorDrivenPropertyChecks with Matchers with TestingCommons {


  def validKey(key: WTKey): Boolean = key.length > 1 && key.length < MaxKeySize

  property("WTree treap stream") {
    val wt = new WTree()(new Blake2b256Unsafe, Level.treapLevel)
    var digest = wt.rootHash()
    forAll { (key: Array[Byte], value: Array[Byte]) =>
      whenever(validKey(key) && value.nonEmpty) {
        digest shouldEqual wt.rootHash()
        val proof: WTModifyProof = wt.modify(key, append(value))
        digest = proof.verify(digest, append(value)).get
      }
    }
  }

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

  property("WTree insert one") {
    forAll { (key: Array[Byte], value: Array[Byte], wrongValue: Array[Byte]) =>
      whenever(validKey(key) && value.nonEmpty) {
        val wt = new WTree()
        val digest = wt.rootHash()
        val proof: WTModifyProof = wt.modify(key, rewrite(value))
        proof.verify(digest, rewrite(value)).get shouldEqual wt.rootHash()
      }
    }
  }

  property("WTree insert") {
    val wt = new WTree()
    forAll { (key: Array[Byte], value: Array[Byte], wrongValue: Array[Byte]) =>
      whenever(validKey(key) && value.nonEmpty) {
        val digest = wt.rootHash()
        val proof: WTModifyProof = wt.modify(key, rewrite(value))
        proof.verify(digest, rewrite(value)).get shouldEqual wt.rootHash()
      }
    }
  }

  property("WTree update") {
    val wt = new WTree()
    forAll { (key: Array[Byte], value: Array[Byte], value2: Array[Byte]) =>
      whenever(validKey(key) && !(value sameElements value2)) {
        val digest1 = wt.rootHash()
        val proof: WTModifyProof = wt.modify(key, append(value))
        proof.verify(digest1, append(value)).get shouldEqual wt.rootHash()

        val digest2 = wt.rootHash()
        val updateProof = wt.modify(key, append(value2))
        updateProof.verify(digest2, append(value2)).get shouldEqual wt.rootHash()
      }
    }
  }

  def rewrite(value: WTValue): UpdateFunction = { oldOpt: Option[WTValue] => value }

  def append(value: WTValue): UpdateFunction = { oldOpt: Option[WTValue] => oldOpt.map(_ ++ value).getOrElse(value) }

  def transactionUpdate(amount: Long): Option[WTValue] => WTValue = (old: Option[WTValue]) =>
    Longs.toByteArray(old.map(v => Longs.fromByteArray(v) + amount).getOrElse(amount))

}
