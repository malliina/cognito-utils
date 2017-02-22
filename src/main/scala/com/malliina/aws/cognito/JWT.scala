package com.malliina.aws.cognito

import java.util.Date

import com.nimbusds.jwt.SignedJWT

import scala.collection.JavaConversions.asScalaBuffer

trait JWT {
  def issuer: Issuer

  def tokenUse: String

  def key: Key

  def expiration: Date

  def signed: SignedJWT

  def claim(name: String): Either[ParseError, Option[String]] =
    Option(signed.getJWTClaimsSet)
      .map(cs => ParsedToken.parseOrError(Option(cs.getStringClaim(name))))
      .getOrElse(Right(None))
}

object JWT {
  val Aud = "aud"
  val ClientId = "client_id"
  val Sub = "sub"
  val UsernameKey = "username"

  def access(verified: VerifiedToken): Either[JWTError, AccessToken] =
    for {
      _ <- compareTokenUse(verified.tokenUse, VerifiedToken.Access)
      clientId <- readClaim(ClientId, verified)
      username <- readClaim(UsernameKey, verified)
      sub <- readClaim(Sub, verified)
    } yield AccessToken(Username(username), App(clientId), sub, verified)

  def id(verified: VerifiedToken): Either[JWTError, IdToken] =
    for {
      _ <- compareTokenUse(verified.tokenUse, VerifiedToken.Id)
      sub <- readClaim(Sub, verified)
      aud <- toEither(Option(verified.signed.getJWTClaimsSet).map(_.getAudience), Aud).right
    } yield IdToken(sub, aud, verified)

  /** Parses and verifies `token`.
    *
    * @param token token to parse and verify
    * @param keys  public keys
    * @return the parsed and verified token or an error
    */
  def verifyToken(token: RawToken, expectedIssuer: Issuer, keys: Seq[PubKey]): Either[JWTError, VerifiedToken] =
    for {
      parsed <- ParsedToken.parse(token).right
      verified <- VerifiedToken.verify(parsed, expectedIssuer, keys).right
    } yield verified

  private def compareTokenUse(value: String, expected: String) = {
    val result =
      if (value == expected) Right(())
      else Left(JWTError.illegalTokenUse(value, expected))
    result.right
  }

  private def readClaim(name: String, jwt: JWT) =
    jwt.claim(name).right.flatMap(o => toEither(o, name)).right

  private def toEither[T](o: Option[T], key: String) =
    o.toRight(DataMissing(key))
}
