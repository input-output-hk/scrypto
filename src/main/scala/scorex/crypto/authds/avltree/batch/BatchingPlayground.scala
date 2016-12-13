package scorex.crypto.authds.avltree

import scorex.crypto.authds.avltree.batch._
import scorex.utils.Random
import scorex.utils.ByteArray
import scala.util.{Failure, Success, Try}



object BatchingPlayground  extends App {
  def time[R](block: => R): (Float, R) = {
    val t0 = System.nanoTime()
    val result = block // call-by-name
    val t1 = System.nanoTime()
    ((t1 - t0).toFloat / 1000000, result)
  }

  
  //smallDeleteTest
  batchingSelfTest
  //deleteProofSizeTest

  //memoryTestWithBatching
  //memoryTestNoBatching
  //timeBenchmarksNew
  //timeBenchmarksOld
  //spaceBenchmarks
  //TestsForInsertAndModifyWithAndWithoutBatching

    
    
  
  

  
  def smallDeleteTest = {
    def intToKey(k : Int) : Array[Byte] = {
      val key = new Array[Byte](32)
      key(0) = k.toByte
      key
    }

    val value = Random.randomBytes(8)
    var newProver = new BatchAVLProver()

    def ins(k: Int) =  {
      var c = Modification.convert((Insert(intToKey(k), value)))
      newProver.performOneModification(c._1, c._2)
      print("Inserted ")
      println(k)
      newProver.checkTree()
      newProver.printTree
    }

    def del(k: Int) =  {
      var c = Modification.convert(Remove(intToKey(k)))
      newProver.performOneModification(c._1, c._2)
      print("Removed ")
      println(k)
      newProver.checkTree()
      newProver.printTree
    }
    
      
    deleteTest2
    
    def deleteTest2 = {
      def makeUnBalanced24EltTree = {
        newProver = new BatchAVLProver
        ins(64)
      
        ins(32)
        ins(96)
      
        ins(16)
        ins(48)
        ins(80)
        ins(112)
      
        ins(8)
        ins(24)
        ins(40)
        ins(56)
        ins(72)
        ins(88)
        ins(104)
        ins(120)
        
        ins(68)
        ins(76)
        ins(84)
        ins(92)
        ins(100)
        ins(108)
        ins(116)
        ins(124)
      }

      makeUnBalanced24EltTree
      del(8)
      del(24)
      del(16)
      
      makeUnBalanced24EltTree
      del(40)
      del(56)
      del(48)  
      
      makeUnBalanced24EltTree
      del(40)
      del(8)
      del(24)
      del(16)

      makeUnBalanced24EltTree
      del(56)
      del(8)
      del(24)
      del(16)

      makeUnBalanced24EltTree
      del(8)
      del(40)
      del(56)
      del(48)  

      makeUnBalanced24EltTree
      del(24)
      del(40)
      del(56)
      del(48)  
               
    }
      
  


    def deleteTest1 = {

      // testCase: 1 for testing deletes of the root, 2 for testing deletes to the left of the root, 3 for testing deletes to the right of the root
    
      val testCase = 3
    
      def clearTree = {
        newProver = new BatchAVLProver()
        if (testCase == 2) {
          ins(60)
          ins(70)
        }
        if (testCase == 3) {
          ins(3)
          ins(2)
        }
      }

      clearTree    
    
      ins(20)


      // testCase *.a no children of the node being removed exist
      del(20)

    
      // testCase *.b: only left child of the node being removed exists
      clearTree
    
      ins(20)
      ins(10)
      del(20)       

    
      // testCase *.c only right child of the node being removed exists    
      clearTree
    
      ins(10)
      ins(20)
      del(10)
    
      // testCase *.d both children of the node being removed exist
      ins(10)
      ins(30)
      del(20)
    
      // testCase *.d.i both children of the node being removed exist, but right is deeper
      ins(8)
      ins(25)
      ins(35)
      del(10)
    
      // clear the tree because balance is all messed up now
      clearTree    
    
      // testCase *.d.ii both children of the node being removed exist and are both deep
      ins(8)
      ins(5)
      ins(30)
      if(testCase == 2)
        ins(65)
      if(testCase == 3)
        ins(1)
      ins(7)
      ins(4)
      ins(25)
      ins(35)
      del(8)
    
      // testCase *.d.iii both children of the node being removed exist but left is deeper
      del(30)
      del(35)
      ins(6)
      del(7)
    }    
    
    
    
  }    
    
    

        

  
  def memoryTestWithBatching {
    // Generate a key out of an int
    def generateKey(i:Int, key:Array[Byte]) {
      val r = i  
      for (j<-0 until 32)
        key(j) = ((r>>((j%4)*8)) % 256).toByte
    }

    val newProver = new BatchAVLProver()
    val numKeys = 400000
    var p : Option[Seq[Byte]] = None
    var prevMemory : Long = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()
    var curMemory : Long = prevMemory
 
    for (i <- 1 until numKeys) {
      val key = new Array[Byte](32)    
      generateKey(i, key)
      val mod =(Insert(key, Random.randomBytes(8)))
      val c = Modification.convert(mod)
      newProver.performOneModification(c._1, c._2)
    }
    newProver.rootHash
    newProver.generateProof
    System.gc
    curMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()
    println(curMemory)

    var i=0
    var j=0
    val key2 = new Array[Byte](32)
    while(true) {
      i+=1
      var increment : Int = Random.randomBytes(1)(0).toInt
      if (increment<0) increment = -increment
      j = (j+increment)%numKeys
      while (j<=0) {
        increment = Random.randomBytes(1)(0)
        if (increment<0) increment = -increment
        j = (j+increment)%numKeys
      }
      generateKey(j, key2)
      val mod =(Update(key2, Random.randomBytes(8)))
      val c = Modification.convert(mod)
      newProver.performOneModification(c._1, c._2) // TODO: IS THIS THE BEST SYNTAX?
      if (i%2000 == 0) {
        newProver.generateProof
        newProver.rootHash
      }
      if (i%50000 == 0) {
        System.gc
        prevMemory = curMemory
        curMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()
        print(i)
        print(",")
        print(curMemory)
        print(",")
        println(curMemory-prevMemory)
      }
    }
  }
/*        
      if (i%2000 == 0) {
        print(i)
        print(",")
        newProver.rootHash
        
        prevMemory = curMemory
        //curMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()
        print(curMemory)
        print(",")
        print(curMemory-prevMemory)
        print(",")
        
        p = Option(newProver.generateProof)
        prevMemory = curMemory
        //curMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()
        print(curMemory-prevMemory)
        print(",")

        //System.gc
        prevMemory = curMemory
        //curMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()
        print(curMemory-prevMemory)
        print(",")

        p = None
        System.gc
        prevMemory = curMemory
        //curMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()
        println(curMemory-prevMemory)        
      }
    }
  }
*/

  def memoryTestNoBatching {
    val oldProver = new AVLTree(32)
    val numMods = 1024*1024
    var p : Option[scala.util.Try[scorex.crypto.authds.avltree.AVLModifyProof]] = None
    var prevMemory : Long = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()
    var curMemory : Long = prevMemory
 
    var i = 0 
    while (true) {
      i+=1
      val mod =(Insert(Random.randomBytes(), Random.randomBytes(8)))
      val c = Modification.convert(mod)
      p=Option(oldProver.modify(c._1, c._2))

      if (i%2000 == 0) {
        print(i)
        print(",")
        oldProver.rootHash
        
        prevMemory = curMemory
        //curMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()
        print(curMemory)
        print(",")
        print(curMemory-prevMemory)
        print(",")

        //System.gc
        prevMemory = curMemory
        //curMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()
        print(curMemory-prevMemory)
        print(",")

        p = None
        System.gc
        prevMemory = curMemory
        //curMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()
        println(curMemory-prevMemory)        
      }
    }
  }
  
  def timeBenchmarksNew {
    val newProver = new BatchAVLProver()
    val numMods = 1024*1024
 
    val mod = new Array[Modification](1)
    for (i <-0 until numMods) {
      mod(0)=(Insert(Random.randomBytes(), Random.randomBytes(8)))
      Modification.convert(mod) foreach (m => newProver.performOneModification(m._1, m._2)) // TODO: IS THIS THE BEST SYNTAX?
      if (i%100000 == 0)
        println(i)
    }
    newProver.rootHash // NOTE: if you comment out this line, the first batch becomes about 2 seconds slower
    newProver.generateProof
    
    val mods = new Array[Modification](75000)
    for (i <- 0 until 75000)
      mods(i) = (Insert(Random.randomBytes(), Random.randomBytes(8)))      
    val converted = Modification.convert(mods)
    
    var i = 0
    for (k<-0 until 10) { //NOTE: if you comment out this loop, the first few batches are slower by factor of 3-6
      val (newProverTime, pf) = time {
        var ctr = 0
        while(ctr<1000) {
          for (j<-0 until 1) {
            newProver.performOneModification(converted(i)._1, converted(i)._2)
            i+=1
            ctr+=1
          }
          newProver.rootHash
          newProver.generateProof.toArray
        }
      }
      println(newProverTime)
    }

    var batchSize = 4096
    while (batchSize > 0) {
      var numBatches = 0
      val (newProverTime, pf) = time {
        var ctr = 0
        while(ctr<4096) {
          for (j<-0 until batchSize) {
            newProver.performOneModification(converted(i)._1, converted(i)._2)
            i+=1
            ctr+=1
          }
          newProver.rootHash
          newProver.generateProof.toArray
          numBatches += 1
        }
      }
      print("batchSize = ")
      print(batchSize)
      print("; numBatches = ")
      print(numBatches)
      print("; newProverTime = ")
      print(newProverTime)
      print("; perInsert = ")
      println(newProverTime/numBatches/batchSize)
      batchSize/=2
    }
  }
  
  
  def timeBenchmarksOld {
    val oldProver = new AVLTree(32)
    val numMods = 1024*1024
 
    val mod = new Array[Modification](1)
    for (i <-0 until numMods) {
      mod(0)=(Insert(Random.randomBytes(), Random.randomBytes(8)))
      Modification.convert(mod) foreach (m => oldProver.modify(m._1, m._2))
      if (i%100000 == 0)
        println(i)
    }
    oldProver.rootHash
    
    val mods = new Array[Modification](75000)
    for (i <- 0 until 75000)
      mods(i) = (Insert(Random.randomBytes(), Random.randomBytes(8)))      
    val converted = Modification.convert(mods)
    
    var i = 0
    for (k<-0 until 10) {
      val (oldProverTime, pf) = time {
        var ctr = 0
        while(ctr<1000) {
          for (j<-0 until 1) {
            oldProver.modify(converted(i)._1, converted(i)._2)
            i+=1
            ctr+=1
          }
          oldProver.rootHash
        }
      }
      println(oldProverTime)
    }

    var batchSize = 4096
    while (batchSize > 0) {
      var numBatches = 0
      val (oldProverTime, pf) = time {
        var ctr = 0
        while(ctr<4096) {
          for (j<-0 until batchSize) {
            oldProver.modify(converted(i)._1, converted(i)._2)
            i+=1
            ctr+=1
          }
          oldProver.rootHash
          numBatches += 1
        }
      }
      print("batchSize = ")
      print(batchSize)
      print("; numBatches = ")
      print(numBatches)
      print("; oldProverTime = ")
      print(oldProverTime)
      print("; perInsert = ")
      println(oldProverTime/numBatches/batchSize)
      batchSize/=2
    }
  }

  // TODO: Add a test that modifies directions and sees verifier reject

  def spaceBenchmarks {
    val newProver = new BatchAVLProver()
  
    val numMods = 1024*1024
 
    val mod = new Array[Modification](1)
    for (i <-0 until numMods) {
      mod(0)=(Insert(Random.randomBytes(), Random.randomBytes(8)))
      Modification.convert(mod) foreach (m => newProver.performOneModification(m._1, m._2)) // TODO: IS THIS THE BEST SYNTAX?
      if (i%10000 == 0)
        println(i)
    }
    val pf = newProver.generateProof.toArray
    println(pf.length)

    var j = 1
    while (j<2000000) {
      for (i <-0 until j) {
        mod(0)=(Insert(Random.randomBytes(), Random.randomBytes(8)))
        Modification.convert(mod) foreach (m => newProver.performOneModification(m._1, m._2)) // TODO: IS THIS THE BEST SYNTAX?
      }
      print("j = ")
      println(j)
      val pf = newProver.generateProof.toArray
      print("proof length ")
      println(pf.length)
      print("proof length per mod ")
      println(pf.length/j)
      j=j*2
    }
  }
 
  def deleteProofSizeTest = {
    val newProver = new BatchAVLProver()
    val numMods = 100000
    val testAtTheEnd = 2000
    
    // TODO: SEE COMMENT IN BIG DELETE TEST ON WHY THIS IS A BAD DATA STRUCTURE TO USE HERE 
    val keys = new scala.collection.mutable.ListBuffer[AVLKey]
    
    for(i <- 0 until numMods) {
      val key = Random.randomBytes()
      keys += key
      val m = Modification.convert(Insert(key, Random.randomBytes(8)))
      newProver.performOneModification(m._1, m._2)
      if (i%50000==0) println(i)
    }
    
    newProver.generateProof

    var len = 0
    for(i <- 0 until testAtTheEnd) {
      val key = Random.randomBytes()
      keys += key
      val m = Modification.convert(Insert(key, Random.randomBytes(8)))
      newProver.performOneModification(m._1, m._2)
    }
    len = newProver.generateProof.toArray.length
    println(len.toFloat/testAtTheEnd)

    len = 0
    for(i <- 0 until testAtTheEnd) {
      val j = Random.randomBytes(3)
      val key = keys((j(0).toInt.abs+j(1).toInt.abs*128+j(2).toInt.abs*128*128) % keys.size)
      keys -= key
      val m = Modification.convert(Remove(key))
      newProver.performOneModification(m._1, m._2)
    }
    len = newProver.generateProof.toArray.length
    println(len.toFloat/testAtTheEnd)

  }
  
  def batchingSelfTest {
    val newProver = new BatchAVLProver()
   
    val numMods = 100000
   
    val deletedKeys = new scala.collection.mutable.ArrayBuffer[AVLKey]

    // TODO: Here we need a data structure that supports fast
    // random access by index; insert, delete, and modify (by index or by value -- we can work with either)
    // Something like a rank tree. I couldn't find anything standard in scala collections,
    // so I am using ArrayBuffer, which is terrible, because delete is slow.
    // ListBuffer would also be terrible here, because it doesn't have
    // fast lookup and remove by index
    // SetTree doesn't allow lookup by rank.
    val keysAndVals = new scala.collection.mutable.ArrayBuffer[(AVLKey, AVLValue)]
    
    var i = 0
    var firstTime = true  // To verify proof on zero modifications
    var numInserts = 0
    var numModifies = 0
    var numDeletes = 0
    
    val t0 = System.nanoTime()
    while (i<numMods) {
      val digest = newProver.rootHash
      var j = 
        if (i==0 && firstTime) {
          firstTime = false;
          0
        } else 
          i+(Random.randomBytes(1))(0).toInt.abs
      val n = j-i
      print("Now making ")
      print(n)
      print(" modifications; total until now ")
      print(i)
      print(". ")
      val currentMods = new scala.collection.mutable.ArrayBuffer[Modification](n)
      while(i<j) {
        if(keysAndVals.size==0 || (Random.randomBytes(1))(0).toInt>0) { // with prob ~.5 insert a new one, with prob ~.5 update or delete an existing one
          val key = Random.randomBytes()
          val newVal = Random.randomBytes(8)
          keysAndVals += ((key, newVal))
          val mod = Insert(key, newVal)
          currentMods+=mod
          val m = Modification.convert(mod)
          newProver.performOneModification(m._1, m._2); 
          newProver.checkTree()
          assert(newProver.unauthenticatedLookup(key).get==newVal) // check insert
          numInserts+=1
        }
        else {
          val j = Random.randomBytes(3)
          // TODO: THIS IS A LAME WAY TO GET A RANDOM KEY -- IMPROVE
          val index = (j(0).toInt.abs+j(1).toInt.abs*128+j(2).toInt.abs*128*128) % keysAndVals.size
          val key = keysAndVals(index)._1
          if ((Random.randomBytes(1))(0).toInt>0) { // with probability .25 update, with .25 delete
            val newVal = Random.randomBytes(8)
            val mod = Update(key, newVal)
            currentMods += mod
            val m = Modification.convert(mod)
            newProver.performOneModification(m._1, m._2);
            keysAndVals(index) = ((key, newVal))
            assert(newProver.unauthenticatedLookup(key).get==newVal) // check update
            numModifies += 1
          } else {
            val mod = Remove(key) 
            val oldVal = keysAndVals(index)._2
            currentMods+=mod
            val m = Modification.convert(mod)
            newProver.performOneModification(m._1, m._2); 
            keysAndVals -= ((key, oldVal))
            deletedKeys += key
            assert(newProver.unauthenticatedLookup(key)==None) // check delete
            numDeletes += 1
          }
        }
        i+=1
      }

      val pf = newProver.generateProof.toArray
      newProver.checkTree(true)
     
      print("Average Proof Length ")
      print(pf.length.toFloat/n)
      if (i>0) {
        print("; time so far = ")
        println((System.nanoTime()-t0)/i)
      }
   
      val newVerifier = new BatchAVLVerifier(digest, pf)
      newVerifier.digest match {
        case None =>
          println("ERROR VERIFICATION FAILED TO CONSTRUCT THE TREE")
          assert(false)
        case Some(d) =>
          assert (d sameElements digest) // Tree built successfully
      }
     
      Modification.convert(currentMods) foreach (m => newVerifier.verifyOneModification(m._1, m._2))
      newVerifier.digest match {
        case None =>
          println("ERROR VERIFICATION FAIL")
          assert(false)
        case Some(d) =>
          assert (d sameElements newProver.rootHash)
      }
    }
    
    // Check that all the inserts, deletes, and updates we did actually stayed 
    deletedKeys foreach (k => assert(newProver.unauthenticatedLookup(k)==None))
    keysAndVals foreach (p => assert(newProver.unauthenticatedLookup(p._1).get==p._2))

    print("NumInserts = ")
    println(numInserts)
    print("NumDeletes = ")
    println(numDeletes)
    print("NumModifies = ")
    println(numModifies)
  }

}

