package scorex.crypto.authds.avltree

import com.google.common.primitives.Longs
import org.scalatest.prop.GeneratorDrivenPropertyChecks
import org.scalatest.{Matchers, PropSpec}

import scorex.crypto.authds.TwoPartyTests


class AVLTreeSpecification extends PropSpec with GeneratorDrivenPropertyChecks with Matchers with TwoPartyTests {


  def validKey(key: AVLKey): Boolean = key.length > 1 && key.length < MaxKeySize

  property("AVLTree performance") {
    val avl = new AVLTree()
    val elements = genElements(1000, 0)
    val avlStats = profileTree(avl, elements, avl.rootHash())
  }


  property("AVLTree stream") {
    val wt = new AVLTree()
    var digest = wt.rootHash()
    forAll { (key: Array[Byte], value: Array[Byte]) =>
      whenever(validKey(key) && value.nonEmpty) {
        digest shouldEqual wt.rootHash()
        val proof = wt.modify(key, append(value))
        digest = proof.verify(digest, append(value)).get
      }
    }
  }

  property("AVLTree insert one") {
    forAll { (key: Array[Byte], value: Array[Byte], wrongValue: Array[Byte]) =>
      whenever(validKey(key) && value.nonEmpty) {
        val wt = new AVLTree()
        val digest = wt.rootHash()
        val proof = wt.modify(key, rewrite(value))
        proof.verify(digest, rewrite(value)).get shouldEqual wt.rootHash()
      }
    }
  }

  property("AVLTree insert") {
    val wt = new AVLTree()
    forAll { (key: Array[Byte], value: Array[Byte], wrongValue: Array[Byte]) =>
      whenever(validKey(key) && value.nonEmpty) {
        val digest = wt.rootHash()
        val proof = wt.modify(key, rewrite(value))
        proof.verify(digest, rewrite(value)).get shouldEqual wt.rootHash()
      }
    }
  }

  property("AVLTree update") {
    val wt = new AVLTree()
    forAll { (key: Array[Byte], value: Array[Byte], value2: Array[Byte]) =>
      whenever(validKey(key) && !(value sameElements value2)) {
        val digest1 = wt.rootHash()
        val proof = wt.modify(key, append(value))
        proof.verify(digest1, append(value)).get shouldEqual wt.rootHash()

        val digest2 = wt.rootHash()
        val updateProof = wt.modify(key, append(value2))
        updateProof.verify(digest2, append(value2)).get shouldEqual wt.rootHash()
      }
    }
  }

  def rewrite(value: AVLValue): UpdateFunction = { oldOpt: Option[AVLValue] => value }

  def transactionUpdate(amount: Long): Option[AVLValue] => AVLValue = (old: Option[AVLValue]) =>
    Longs.toByteArray(old.map(v => Longs.fromByteArray(v) + amount).getOrElse(amount))

}
