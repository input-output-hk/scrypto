package scorex

import org.scalatest.matchers.should.Matchers
import org.scalatest.propspec.AnyPropSpec

import java.io.{StringWriter, PrintWriter}
import java.lang.annotation.{ElementType, Target}
import java.lang.reflect.{InvocationTargetException, UndeclaredThrowableException}
import java.nio.ByteBuffer
import scala.collection.mutable
import scala.reflect.ClassTag

class ScalaJsSpec extends AnyPropSpec with Matchers {
  class A {
    val f: Int = 10
    def m(): String = "m.toString"
  }
  class Z extends A

  val x = new A
  val y = new A
  val z = new Z
  val cls = x.getClass
  val clsY = y.getClass
  val clsZ = z.getClass

  property("getSimpleName") {
    cls shouldNot be(null)
    cls.getSimpleName shouldBe "A"
    // cls.getEnclosingClass shouldNot be (null) // Referring to non-existent method java.lang.Class.getEnclosingClass()
    println(cls)
  }

  property("getName") {
    cls.getName shouldBe "scorex.ScalaJsSpec$A"
    val t = mutable.HashMap.empty[Class[_], Int]
    t.put(cls, 1)
    t.get(clsY) shouldBe Some(1)
  }

//  property("getField") {
////    cls.getField("f") shouldNot be(null) // Referring to non-existent method java.lang.Class.getField(java.lang.String)
//  }
//
//  property("getConstructors") {
////    cls.getConstructors shouldNot be(null) // Referring to non-existent method java.lang.Class.getConstructors()
//  }

  property("isPrimitive") {
    cls.isPrimitive shouldBe false
    classOf[Int].isPrimitive shouldBe true
  }

  property("getSuperclass") {
    cls.getSuperclass.getName shouldBe "java.lang.Object"
  }

  property("isAssignableFrom") {
    cls.isAssignableFrom(clsY) shouldBe true
    cls.isAssignableFrom(classOf[java.lang.Object]) shouldBe false
    cls.isAssignableFrom(clsZ) shouldBe true
  }

  property("PrintWriter") {
    val pr = new PrintWriter(new StringWriter(100))
    pr.println("test")
  }

  property("ByteBuffer") {
    val bytes = Array[Byte](1, 2, 3)
    val buf = ByteBuffer.wrap(bytes)
    buf.position() shouldBe 0
  }

//  property("InvocationTargetException") {
//    // [error] Referring to non-existent class java.lang.reflect.InvocationTargetException
//    an[InvocationTargetException] should be thrownBy(throw new InvocationTargetException(null))
//  }

//  property("UndeclaredThrowableException") {
//    // [error] Referring to non-existent class java.lang.reflect.UndeclaredThrowableException
//    an[UndeclaredThrowableException] should be thrownBy(throw new UndeclaredThrowableException(null))
//  }

  property("ExceptionInInitializerError") {
    // [error] Referring to non-existent class java.lang.reflect.UndeclaredThrowableException
    an[ExceptionInInitializerError] should be thrownBy(throw new ExceptionInInitializerError("error"))
  }

  property("ClassTag") {
    val t = ClassTag[String](classOf[String])
    t.toString() shouldBe "java.lang.String"
  }

  property("ClassTag.runtimeClass") {
    val t = ClassTag[String](classOf[String])
    t.runtimeClass shouldBe classOf[String]
  }

  property("NoSuchMethodException") {
    try {
      throw new NoSuchMethodException("methodName")
      assert(false)
    }
    catch {
      case e: NoSuchMethodException =>
        e.getMessage shouldBe "methodName"
    }
  }

}
