package tsec.mac.imports

import javax.crypto.Mac

import cats.effect.Sync
import cats.syntax.all._
import java.util.concurrent.{ConcurrentLinkedQueue => JQueue}

import tsec.mac.core.{MacAlgebra, MacTag}

sealed protected[tsec] abstract class JMacPureInterpreter[F[_], A](tl: JQueue[Mac])(
    implicit F: Sync[F],
    macTag: MacTag[A]
) extends MacAlgebra[F, A, MacSigningKey] {
  type M = Mac

  def genInstance: F[Mac] =
    F.delay {
      val inst = tl.poll()
      if (inst != null)
        inst
      else
        Mac.getInstance(macTag.algorithm)
    }

  def sign(content: Array[Byte], key: MacSigningKey[A]): F[Array[Byte]] =
    for {
      instance <- genInstance
      _        <- F.delay(instance.init(MacSigningKey.toJavaKey[A](key)))
      fin      <- F.delay(instance.doFinal(content))
      _        <- F.delay(tl.add(instance))
    } yield fin
}

object JMacPureInterpreter {
  def apply[F[_]: Sync, A](numInstances: Int = 10)(implicit tag: MacTag[A]) = {
    val queue = new JQueue[Mac]()
    var i     = 0
    while (i < numInstances) {
      queue.add(Mac.getInstance(tag.algorithm))
      i += 1
    }
    new JMacPureInterpreter[F, A](queue) {}
  }

  implicit def gen[F[_]: Sync, A: MacTag]: JMacPureInterpreter[F, A] = apply[F, A]()
}
