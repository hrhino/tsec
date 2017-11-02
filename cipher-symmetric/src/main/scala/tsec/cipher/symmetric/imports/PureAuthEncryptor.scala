package tsec.cipher.symmetric.imports

import cats.effect.Sync
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.imports.aead.JCAAEADPure
import tsec.cipher.common.padding.NoPadding

sealed abstract case class PureAuthEncryptor[F[_], A: AEADCipher](
    instance: JCAAEADPure[F, A, GCM, NoPadding]
)(implicit F: Sync[F], keyGenerator: CipherKeyGen[A]) {

  @inline
  def keyGen: CipherKeyGen[A] = keyGenerator

  def fromSingleArray(bytes: Array[Byte]): F[CipherText[A, GCM, NoPadding]] =
    F.fromEither(CipherText.fromSingleArray[A, GCM, NoPadding](bytes))
}

object PureAuthEncryptor {
  def apply[F[_], A: AEADCipher: CipherKeyGen](implicit F: Sync[F]): F[PureAuthEncryptor[F, A]] =
    F.map(JCAAEADPure[F, A, GCM, NoPadding]()) { inst =>
      new PureAuthEncryptor[F, A](inst) {}
    }
}