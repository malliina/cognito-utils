package com.malliina.aws.cognito

import java.math.BigInteger
import java.security.KeyFactory
import java.security.interfaces.RSAPublicKey
import java.security.spec.RSAPublicKeySpec
import java.util.Base64

object Keys {
  val keyFactory = KeyFactory.getInstance("RSA")

  def publicKey(key: JWTKey): RSAPublicKey =
    publicKey(toBigInt(key.n), toBigInt(key.e))

  private def publicKey(modulus: BigInteger, exponent: BigInteger): RSAPublicKey = {
    val keySpec = new RSAPublicKeySpec(modulus, exponent)
    keyFactory.generatePublic(keySpec).asInstanceOf[RSAPublicKey]
  }

  private def toBigInt(enc: String): BigInteger =
    new BigInteger(1, Base64.getUrlDecoder.decode(enc))
}
