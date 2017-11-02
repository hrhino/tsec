package tsec.cookies

import cats.data.OptionT
import cats.effect.Sync
import tsec.common._
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.imports._
import cats.syntax.all._

object AEADCookieEncryptor {

  /** Sign and encrypt a cookie for some A, with the format:
    * (Encrypted Content)-(AAD)
    */
  def signAndEncrypt[A: AEADCipher](message: String, aad: AAD, key: SecretKey[A])(
      implicit authEncryptor: AuthEncryptor[A]
  ): Either[CipherError, AEADCookie[A]] =
    if (message.isEmpty)
      Left(EncryptError("Cannot encrypt an empty string!"))
    else
      for {
        instance  <- authEncryptor.instance
        encrypted <- instance.encryptAAD(PlainText(message.utf8Bytes), key, aad)
      } yield AEADCookie.fromEncrypted[A](encrypted, aad)

  /** Retrieve the contents of the signed cookie message
    *
    * @return
    */
  def retrieveFromSigned[A: AEADCipher](message: AEADCookie[A], key: SecretKey[A])(
      implicit authEncryptor: AuthEncryptor[A]
  ): Either[CipherError, String] = {
    val split = message.split("-")
    if (split.length != 2)
      Left(DecryptError("Could not decode cookie"))
    else {
      val aad = AAD(split(1).base64Bytes)
      for {
        instance   <- authEncryptor.instance
        cipherText <- authEncryptor.fromSingleArray(split(0).base64Bytes)
        decrypted  <- instance.decryptAAD(cipherText, key, aad)
      } yield decrypted.content.toUtf8String
    }
  }

  /** Same as the other function, but kept protected to not muddy the api too much,
    * to be used internally by the encrypted cookie authenticator
    *
    */
  protected[tsec] def signAndEncryptF[F[_], A: AEADCipher](
      message: String,
      aad: AAD,
      key: SecretKey[A],
      encryptor: PureAuthEncryptor[F, A]
  )(implicit F: Sync[F]): OptionT[F, AEADCookie[A]] =
    if (message.isEmpty)
      OptionT.none
    else
      OptionT
        .liftF(
          encryptor.instance
            .encryptAAD(PlainText(message.utf8Bytes), key, aad)
            .map(AEADCookie.fromEncrypted[A](_, aad))
        )
        .handleErrorWith(_ => OptionT.none)

  /** Same as the other function, but kept protected to not muddy the api too much,
    * to be used internally by the encrypted cookie authenticator
    *
    */
  def retrieveFromSignedF[F[_], A: AEADCipher](
      message: AEADCookie[A],
      key: SecretKey[A],
      encryptor: PureAuthEncryptor[F, A]
  )(
      implicit F: Sync[F],
  ): OptionT[F, String] = {
    val split = message.split("-")
    if (split.length != 2)
      OptionT.none
    else {
      val aad = AAD(split(1).base64Bytes)
      OptionT
        .liftF(for {
          cipherText <- encryptor.fromSingleArray(split(0).base64Bytes)
          decrypted  <- encryptor.instance.decryptAAD(cipherText, key, aad)
        } yield decrypted.content.toUtf8String)
        .handleErrorWith(_ => OptionT.none)
    }
  }

}
