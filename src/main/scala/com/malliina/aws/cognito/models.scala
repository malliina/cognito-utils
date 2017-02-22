package com.malliina.aws.cognito

import java.security.interfaces.RSAPublicKey

import play.api.libs.json.{Format, Json, Reads, Writes}

abstract class WrappedString(val value: String) {
  override def toString = value
}

trait Wrapped[T <: WrappedString] {
  def apply(raw: String): T

  def write(t: T): String = t.value

  implicit val json: Format[T] = Format[T](
    Reads(_.validate[String].map(apply)),
    Writes(t => Json.toJson(write(t)))
  )
}

case class Username(user: String) extends WrappedString(user)

case class Password(pass: String) extends WrappedString(pass)

case class Issuer(iss: String) extends WrappedString(iss)

object Issuer extends Wrapped[Issuer]

case class UserPool(id: String) extends WrappedString(id)

case class App(id: String) extends WrappedString(id)

case class Key(id: String) extends WrappedString(id)

object Key extends Wrapped[Key]

trait RawToken {
  def token: String

  override def toString: String = token
}

case class RawAccessToken(token: String) extends RawToken

case class RefreshToken(token: String) extends RawToken

case class RawIDToken(token: String) extends RawToken

case class JWTKey(alg: String,
                  e: String,
                  kid: Key,
                  kty: String,
                  n: String,
                  use: String)

object JWTKey {
  implicit val json = Json.format[JWTKey]
}

case class JWTKeys(keys: Seq[JWTKey])

object JWTKeys {
  implicit val json = Json.format[JWTKeys]
}

case class PubKey(id: Key, publicKey: RSAPublicKey)
