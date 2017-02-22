package com.malliina.aws.cognito

import java.text.ParseException
import java.util.Date

import com.nimbusds.jwt.SignedJWT

import scala.util.Either.RightProjection
import scala.util.Try

case class ParsedToken(issuer: Issuer,
                       tokenUse: String,
                       key: Key,
                       expiration: Date,
                       signed: SignedJWT) extends JWT

object ParsedToken {
  val TokenUse = "token_use"

  /** Parses but does not verify a JSON Web Token.
    *
    * @param token token to parse
    * @return a parsed token or an error
    */
  def parse(token: RawToken): Either[JWTError, ParsedToken] =
    for {
      signed <- parseToken(token).right
      claims <- mustExist(signed.getJWTClaimsSet, failInfo = "claims")
      issuer <- mustExist(claims.getIssuer, "issuer")
      tokenUse <- mustExist(Try(claims.getStringClaim(TokenUse)).toOption.orNull, TokenUse)
      key <- mustExist(signed.getHeader.getKeyID, "key")
      expiration <- mustExist(claims.getExpirationTime, "expiration")
    } yield {
      ParsedToken(Issuer(issuer), tokenUse, Key(key), expiration, signed)
    }

  // Parsing helpers

  def parseToken(token: RawToken): Either[ParseError, SignedJWT] =
    parseOrError(SignedJWT.parse(token.token), _ => s"Invalid JWT: '$token'.")

  def parseOrError[T](code: => T): Either[ParseError, T] =
    parseOrError(code, e => Option(e.getMessage).getOrElse("Parse error."))

  def parseOrError[T](code: => T, errorMessage: ParseException => String): Either[ParseError, T] =
    try {
      Right(code)
    } catch {
      case e: ParseException =>
        Left(ParseError(errorMessage(e), e))
    }

  def mustExist[T](nullable: => T, failInfo: String): RightProjection[DataMissing, T] =
    Utils.mustExist(nullable, DataMissing(failInfo))
}
