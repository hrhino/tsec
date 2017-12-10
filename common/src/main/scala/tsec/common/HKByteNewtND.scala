package tsec.common

/** A higher kinded existential newt,
  * without compiler dealias.
  */
private[tsec] trait HKByteNewtND {

  type Repr[A]

  def is[A]: cats.evidence.Is[Array[Byte], Repr[A]]
}
