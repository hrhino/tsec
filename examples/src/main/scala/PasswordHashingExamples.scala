object PasswordHashingExamples {

  import cats.effect.IO
  import tsec.passwordhashers._
  import tsec.passwordhashers.imports._

  /** For password hashers, you have three options: BCrypt, SCrypt and HardenedScrypt
    * (Which is basically scrypt but with much more secure parameters, but a lot slower).
    */
  val pass: Array[Char] = Array('h', 'e', 'l', 'l', 'o', 'w', 'o', 'r', 'l', 'd')

  /**
    * Preferrably, though, you'd want to receive your password as an `Array[Byte]` or
    * `Array[Char]` without ever storing a string. TSec
    * handles this case first and foremost
    */
  val bestbcryptHash: IO[PasswordHash[BCrypt]]                 = BCrypt.hashpw[IO](pass)
  val bestscryptHash: IO[PasswordHash[SCrypt]]                 = SCrypt.hashpw[IO](pass)
  val besthardenedScryptHash: IO[PasswordHash[HardenedSCrypt]] = HardenedSCrypt.hashpw[IO](pass)

  val bcryptHash: IO[PasswordHash[BCrypt]]                 = BCrypt.hashpw[IO]("hiThere")
  val scryptHash: IO[PasswordHash[SCrypt]]                 = SCrypt.hashpw[IO]("hiThere")
  val hardenedScryptHash: IO[PasswordHash[HardenedSCrypt]] = HardenedSCrypt.hashpw[IO]("hiThere")

  /**
    *
    */
  /** To Validate, you can check against a hash! */
  val checkProgram: IO[Boolean] = for {
    hash  <- bcryptHash
    check <- BCrypt.checkpw[IO]("hiThere", hash)
  } yield check

  /** Alternatively if FP is your enemy, you can use the unsafe methods
    *
    */
  val unsafeHash: PasswordHash[BCrypt] = BCrypt.hashpwUnsafe("hiThere")
  val unsafeCheck: Boolean             = BCrypt.checkpwUnsafe("hiThere", unsafeHash)

  /** Note: The following syntax has now been deprecated since
    * 0.0.1-M6,
    * as it is mutating and possibly throws an errror
    *
    */
  val oldbcryptHash: PasswordHash[BCrypt]                 = "hiThere".hashPassword[BCrypt]
  val oldscryptHash: PasswordHash[SCrypt]                 = "hiThere".hashPassword[SCrypt]
  val oldhardenedScryptHash: PasswordHash[HardenedSCrypt] = "hiThere".hashPassword[HardenedSCrypt]

  /** To Validate, you can check against a hash! */
  val oldcheck: Boolean = "hiThere".checkWithHash[BCrypt](oldbcryptHash)

}
