package tsec.util

object newt {

  abstract class ByteArray {
    type Type <: Array[Byte]

    @inline final def apply(value: Array[Byte]): Type             = value.asInstanceOf[Type]
    @inline final def subst[F[_]](value: F[Array[Byte]]): F[Type] = value.asInstanceOf[F[Type]]
  }

  abstract class ByteArrayHK {
    type Type[A]  <: Array[Byte]

    @inline final def apply[A](value: Array[Byte]): Type[A] = value.asInstanceOf[Type[A]]
    @inline final def subst[A]                              = new NewtSubst_*->*[Type, A, Array[Byte]]
    @inline final def unsubst[A]                            = new NewtUnsubst_*->*[Type, A, Array[Byte]]
  }

  final class NewtSubst_*->*[T[_], A, R] private[newt] (private val fnord: Unit = ()) extends AnyVal {
    @inline def apply[F[_]](value: F[R]): F[T[A]] = value.asInstanceOf[F[T[A]]]
  }

  final class NewtUnsubst_*->*[T[_], A, R] private[newt] (private val dummy: Boolean = true) extends AnyVal {
    @inline def apply[F[_]](value: F[T[A]]): F[R] = value.asInstanceOf[F[R]]
  }

}

