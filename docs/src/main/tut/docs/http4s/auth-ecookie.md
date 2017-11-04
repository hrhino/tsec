---
layout: docs
number: 7
title: "Encrypted cookie auth"
---
# Encrypted cookie authentication

### Setup

In our example, we will use a dummy backing store, to simulate a data transfer class or object:

```tut:silent
import java.util.UUID
import cats._
import cats.data.OptionT
import cats.effect.IO
import org.http4s.HttpService
import tsec.authentication._
import tsec.authorization._
import tsec.cipher.symmetric.imports._
import scala.collection.mutable
import scala.concurrent.duration._
import org.http4s.dsl.io._


def dummyBackingStore[F[_], I, V](getId: V => I)(implicit F: Monad[F]) = new BackingStore[F, I, V] {
    private val storageMap = mutable.HashMap.empty[I, V]

    def put(elem: V): F[Int] = {
      val map = storageMap.put(getId(elem), elem)
      if (map.isEmpty)
        F.pure(0)
      else
        F.pure(1)
    }

    def get(id: I): OptionT[F, V] =
      OptionT.fromOption[F](storageMap.get(id))

    def update(v: V): F[Int] = {
      storageMap.update(getId(v), v)
      F.pure(1)
    }

    def delete(id: I): F[Int] =
      storageMap.remove(id) match {
        case Some(_) => F.pure(1)
        case None    => F.pure(0)
      }
  }
```

### Our Example user class + SimpleAuthEnum

We will demonstrate how to use SimpleAuthEnum, as well as Role based authorization. A note about SimpleAuthEnum:
If you place the subtypes of the sealed trait Enum inside of the companion object for the trait, you must set them as 
implicit, or else you will suffer a `knownDirectSubclasses` bug as seen in the discussion [here](https://github.com/circe/circe/issues/639)

The following will be the user class used for this example

```tut:silent
 sealed abstract class Role(val roleRepr: String)
 
 object Role extends SimpleAuthEnum[Role, String] {
    implicit case object Administrator extends Role("Administrator")
    implicit case object Customer      extends Role("User")
    implicit case object Seller        extends Role("Seller")
    implicit case object CorruptedData extends Role("corrupted")

    implicit val E: Eq[Role]      = Eq.fromUniversalEquals[Role]
    val getRepr: (Role) => String = _.roleRepr

    protected val values: AuthGroup[Role] = AuthGroup(Administrator, Customer, Seller)
    val orElse: Role                      = CorruptedData
 }

  case class User(id: Int, age: Int, name: String, role: Role = Role.Customer)

  object User {
    implicit def authRole[F[_]](implicit F: MonadError[F, Throwable]): AuthorizationInfo[F, User, Role] =
      new AuthorizationInfo[F, User, Role] {
        def fetchInfo(u: User): F[Role] = F.pure(u.role)
      }
  }
  
  val cookieBackingStore: BackingStore[IO, UUID, AuthEncryptedCookie[AES128, Int]] =
    dummyBackingStore[IO, UUID, AuthEncryptedCookie[AES128, Int]](_.id)


  val userStore: BackingStore[IO, Int, User] = dummyBackingStore[IO, Int, User](_.id)
  
  //Note, the next two imports are not necessary outside the repl, that doesn't resolve implicits without this
  import User._ 
  import Role._ 
```
### Authenticator creation
From here, if want want to create services, we simply use the request handler we created
(Note: Since the type of the service is `HttpService[IO]`, we can mount it like any other endpoint!):

```tut:silent

  val settings: TSecCookieSettings = TSecCookieSettings(
    cookieName = "tsec-auth",
    secure = false,
    expiryDuration = 10.minutes, // Absolute expiration time
    maxIdle = None // Rolling window expiration. Set this to a Finiteduration if you intend to have one
  )

  val key: SecretKey[AES128] = AES128.generateKeyUnsafe() //Our encryption key

  val encryptedCookieAuth =
    EncryptedCookieAuthenticator.withBackingStore(
      settings,
      cookieBackingStore,
      userStore,
      key
    )

  val Auth =
    SecuredRequestHandler.encryptedCookie(encryptedCookieAuth)

  val onlyAdmins      = BasicRBAC[IO, User, Role](Role.Administrator, Role.Customer)
  val adminsAndSeller = BasicRBAC[IO, User, Role](Role.Administrator, Role.Seller)

  val service: HttpService[IO] = Auth {
    case request @ GET -> Root / "api" asAuthed user =>
      /*
      Note: The request is of type: SecuredRequest, which carries:
      1. The request
      2. The Authenticator (i.e token)
      3. The identity (i.e in this case, User)
       */
      val r: SecuredRequest[IO, AuthEncryptedCookie[AES128, Int], User] = request
      Ok()
  }

 val authorizedService: HttpService[IO] = Auth.authorized(onlyAdmins) {
    case request @ GET -> Root / "api" asAuthed user =>
      Ok(user.role.roleRepr)
  }
```