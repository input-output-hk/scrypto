package scorex.crypto.authds.merkle.versioned

import org.h2.mvstore.MVStore
import org.scalacheck.Gen
import org.scalatest.prop.{GeneratorDrivenPropertyChecks, PropertyChecks}
import org.scalatest.{Matchers, PropSpec}


class MvStoreSpecification
  extends PropSpec
  with PropertyChecks
  with GeneratorDrivenPropertyChecks
  with Matchers {

  property("correct rollback") {
    val s = MVStore.open(null)
    val map = s.openMap[Int, String]("data")

    s.setVersionsToKeep(51)

    // add some data
    map.put(1, "Hello")
    map.put(2, "World")

    s.commit()

    // get the current version, for later use
    val initVersion = s.getCurrentVersion()

    forAll(Gen.listOf(Gen.alphaStr), minSuccessful(50), maxDiscarded(1)) { strings: List[String] =>
      strings.zipWithIndex.foreach { case (str, i) =>
        map.put(map.size() + i, str)
      }
      s.commit()
    }

    map.openVersion(initVersion).size() shouldBe 2
    s.rollbackTo(initVersion)
    map.size() shouldBe 2
  }

}
