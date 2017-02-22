package com.malliina.aws.cognito

import java.text.ParseException
import java.util.Date

import com.amazonaws.services.cognitoidp.model.{AWSCognitoIdentityProviderException, AuthenticationResultType, ChallengeNameType}

sealed abstract class JWTError(val message: String)

object JWTError {
  def illegalTokenUse(value: String, expected: String) =
    illegal(ParsedToken.TokenUse, value, s"'$expected'")

  def unknownTokenUse(value: String) =
    illegal(ParsedToken.TokenUse, value, s"one of ${VerifiedToken.TokenUseValues.mkString("'", "', '", "'")}")

  def illegal(key: String, value: String, expected: String) =
    IllegalValue(s"Illegal $key value: '$value', must be $expected.")
}

case class ParseError(info: String, e: ParseException)
  extends JWTError(info)

case class UnknownPublicKey(key: Key)
  extends JWTError(s"Unknown key: '$key'.")

case class DataMissing(info: String)
  extends JWTError(info)

case class IllegalValue(info: String)
  extends JWTError(info)

case class VerifyError(key: Key)
  extends JWTError(s"Verification of key '$key' failed.")

case class TokenExpired(expiration: Date)
  extends JWTError(s"Token expired at '$expiration'.")

case class IssuerMismatch(actual: Issuer, expected: Issuer)
  extends JWTError(s"Invalid issuer: '$actual', expected: '$expected'.")

sealed abstract class CognitoError(val message: String)

case class CognitoException(exception: AWSCognitoIdentityProviderException)
  extends CognitoError(exception.getMessage)

case class CognitoDataMissing(info: String)
  extends CognitoError(info)

case class AuthResultFailure(info: String, result: AuthenticationResultType)
  extends CognitoError(info)

case class Challenge(name: ChallengeNameType, result: AuthResult)
  extends CognitoError(s"Got challenge '$name'.") {
  def session: String = result.session
}
