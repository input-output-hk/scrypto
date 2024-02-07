package scorex.crypto.authds.avltree.batch

import org.scalatest.matchers.should.Matchers
import scorex.crypto.authds.{ADKey, ADValue}
import scorex.crypto.hash.{Blake2b256, Digest, Digest32}
import scorex.utils.Random

trait BatchTestingHelpers extends ToStringHelper with Matchers {

  val InitialTreeSize = 1000

  val KL = 32
  val VL = 8
  type D = Digest32
  type HF = Blake2b256.type

  def randomKey(size: Int = 32): ADKey = ADKey @@ Random.randomBytes(size)

  def randomValue(size: Int = 32): ADValue = ADValue @@ Random.randomBytes(size)

  def generateProver(size: Int = InitialTreeSize): (BatchAVLProver[D, HF], Seq[(ADKey, ADValue)]) = {
    val prover = new BatchAVLProver[D, HF](KL, None)
    val initialElements: Seq[(ADKey, ADValue)] = (0 until size) map { i =>
      (ADKey @@ Blake2b256(i.toString.getBytes("UTF-8")).take(KL), ADValue @@ (i.toString.getBytes("UTF-8")))
    }
    initialElements.foreach(kv => prover.performOneOperation(Insert(kv._1, kv._2)))
    prover.generateProof()
    (prover, initialElements)
  }

  /**
    * check, that removedNodes contains all nodes, that are where removed, and do not contain nodes, that are still in the tree
    */
  def checkTree(prover: BatchAVLProver[D, HF], oldTop: ProverNodes[D], removedNodes: Seq[ProverNodes[D]]): Unit = {
    // check that there are no nodes in removedNodes, that are still in the tree
    removedNodes.foreach{r =>
      if(prover.contains(r)) {
        throw new Error(s"Node $r is marked to remove while still in the tree")
      }
    }

    var removed = 0

    // check that all removed nodes are in removedNodes list
    def checkRemoved(node: ProverNodes[D]): Unit = {
      val contains = prover.contains(node)
      if (!contains) removed = removed + 1
      if (!contains && !removedNodes.exists(_.label sameElements node.label)) {
        throw new Error(s"Node $node is not in the new tree but is not in removedNodes list")
      }

      node match {
        case i: InternalProverNode[D] =>
          checkRemoved(i.left)
          checkRemoved(i.right)
        case _ =>
        // do nothing
      }
    }

    checkRemoved(oldTop)
    removed shouldBe removedNodes.length
  }


  def pathToString(path: Seq[ProverNodes[D]]): String = {
    def loop(prevNode: ProverNodes[D], remaining: Seq[ProverNodes[D]], acc: Seq[String]): Seq[String] = {
      if (remaining.nonEmpty) {
        prevNode match {
          case pn: InternalProverNode[D] =>
            val n = remaining.head
            val direction = if (n.label sameElements pn.left.label) "L" else "R"


            val newAcc = s"$direction-${arrayToString(n.label)}" +: acc
            loop(n, remaining.tail, newAcc)
          case _ => ???
        }
      } else {
        acc
      }
    }

    loop(path.head, path.tail, Seq(arrayToString(path.head.label))).reverse.mkString(",")
  }

}
