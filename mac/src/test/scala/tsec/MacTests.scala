package tsec

import cats.effect.IO
import org.scalatest.MustMatchers
import tsec.common._
import tsec.common.JKeyGenerator
import tsec.mac.core.MacTag
import tsec.mac.imports.{MacSigningKey, _}

class MacTests extends TestSpec with MustMatchers {

  def macTest[T](implicit keyGen: JKeyGenerator[T, MacSigningKey, MacKeyBuildError], tag: MacTag[T]): Unit = {
    behavior of tag.algorithm

    val instance = JCAMacImpure[T]

    it should "Sign then verify the same encrypted data properly" in {
      val dataToSign = "awwwwwwwwwwwwwwwwwwwwwww YEAH".utf8Bytes

      val res: Either[Throwable, Boolean] = for {
        k        <- keyGen.generateKey()
        signed   <- instance.sign(dataToSign, k)
        verified <- instance.verify(dataToSign, signed, k)
      } yield verified

      res mustBe Right(true)
    }

    it should "sign to the same message" in {
      val dataToSign = "awwwwwwwwwwwwwwwwwwwwwww YEAH".utf8Bytes

      val res: Either[Throwable, Boolean] = for {
        k       <- keyGen.generateKey()
        signed1 <- instance.algebra.sign(dataToSign, k)
        signed2 <- instance.algebra.sign(dataToSign, k)
      } yield ByteUtils.constantTimeEquals(signed1, signed2)
      res mustBe Right(true)
    }

    it should "not verify for different messages" in {
      val dataToSign = "awwwwwwwwwwwwwwwwwwwwwww YEAH".utf8Bytes
      val incorrect  = "hello my kekistanis".utf8Bytes

      val res: Either[Throwable, Boolean] = for {
        k       <- keyGen.generateKey()
        signed1 <- instance.sign(dataToSign, k)
        cond    <- instance.verify(incorrect, signed1, k)
      } yield cond

      res mustBe Right(false)
    }

    it should "not verify for different keys" in {

      val dataToSign = "awwwwwwwwwwwwwwwwwwwwwww YEAH".utf8Bytes

      val res: Either[Throwable, Boolean] = for {
        k       <- keyGen.generateKey()
        k2      <- keyGen.generateKey()
        signed1 <- instance.sign(dataToSign, k)
        cond    <- instance.verify(dataToSign, signed1, k2)
      } yield cond

      res mustBe Right(false)

    }

    /*
    Pure tests
     */
    val pureinstance = JCAMacPure[IO, T]

    behavior of (tag.algorithm + " pure interpreter")

    it should "Sign then verify the same encrypted data properly" in {
      val dataToSign = "awwwwwwwwwwwwwwwwwwwwwww YEAH".utf8Bytes

      val res = for {
        k        <- keyGen.generateLift[IO]
        signed   <- pureinstance.sign(dataToSign, k)
        verified <- pureinstance.verify(dataToSign, signed, k)
      } yield verified

      res.unsafeRunSync() mustBe true
    }

    it should "sign to the same message" in {
      val dataToSign = "awwwwwwwwwwwwwwwwwwwwwww YEAH".utf8Bytes

      val res: IO[Boolean] = for {
        k       <- keyGen.generateLift[IO]
        signed1 <- pureinstance.algebra.sign(dataToSign, k)
        signed2 <- pureinstance.algebra.sign(dataToSign, k)
      } yield ByteUtils.constantTimeEquals(signed1, signed2)
      res.unsafeRunSync() mustBe true
    }

    it should "not verify for different messages" in {
      val dataToSign = "awwwwwwwwwwwwwwwwwwwwwww YEAH".utf8Bytes
      val incorrect  = "hello my kekistanis".utf8Bytes

      val res = for {
        k       <- keyGen.generateLift[IO]
        signed1 <- pureinstance.sign(dataToSign, k)
        cond    <- pureinstance.verify(incorrect, signed1, k)
      } yield cond

      res.unsafeRunSync() mustBe false
    }

    it should "not verify for different keys" in {

      val dataToSign = "awwwwwwwwwwwwwwwwwwwwwww YEAH".utf8Bytes

      val res = for {
        k       <- keyGen.generateLift[IO]
        k2      <- keyGen.generateLift[IO]
        signed1 <- pureinstance.sign(dataToSign, k)
        cond    <- pureinstance.verify(dataToSign, signed1, k2)
      } yield cond

      res.unsafeRunSync() mustBe false

    }
  }

  macTest[HMACSHA1]
  macTest[HMACSHA256]
  macTest[HMACSHA384]
  macTest[HMACSHA512]

}
