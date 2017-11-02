package tsec.cipher.symmetric.imports

import cats.effect.Sync
import tsec.cipher.symmetric._
import tsec.cipher.common.padding.NoPadding

sealed abstract case class PureEncryptor[F[_], A: SymmetricCipher](
    instance: JCASymmPure[F, A, CTR, NoPadding],
)(implicit F: Sync[F], keyGenerator: CipherKeyGen[A]) {
  @inline def keyGen: CipherKeyGen[A] = keyGenerator

  def fromSingleArray(bytes: Array[Byte]): F[CipherText[A, CTR, NoPadding]] =
    F.fromEither(CipherText.fromSingleArray[A, CTR, NoPadding](bytes))
}

object PureEncryptor {
  def apply[F[_], A: SymmetricCipher: CipherKeyGen](implicit F: Sync[F]): F[PureEncryptor[F, A]] =
    F.map(JCASymmPure[F, A, CTR, NoPadding]()) { inst =>
      new PureEncryptor[F, A](inst) {}
    }
}
