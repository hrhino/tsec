package tsec.internal

import cats.effect.Sync
import jnr.ffi.LibraryLoader
import jnr.ffi.Platform
import jnr.ffi.annotations.In
import jnr.ffi.annotations.Out
import jnr.ffi.byref.LongLongByReference
import jnr.ffi.types.u_int64_t
import jnr.ffi.types.u_int8_t
import jnr.ffi.types.size_t

/**
  * https://github.com/jedisct1/libsodium/blob/master/src/libsodium/include/sodium/crypto_auth_hmacsha512.h
  */
private[tsec] trait HmacSha512 {

  def crypto_auth_hmacsha512(
      @Out out: Array[Byte],
      @In in: Array[Byte],
      @In @u_int64_t inlen: Int,
      @In k: Array[Byte]
  ): Int

  def crypto_auth_hmacsha512_verify(
      @Out out: Array[Byte],
      @In in: Array[Byte],
      @In @u_int64_t inlen: Int,
      @In k: Array[Byte]
  ): Int
}

private[tsec] trait HmacSha512Constants {

  val crypto_auth_hmacsha512_BYTES = 64L

  val crypto_auth_hmacsha512_KEYBYTES = 32L
}