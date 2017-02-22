package com.malliina.aws.cognito

import com.amazonaws.services.cognitoidp.model.{AdminInitiateAuthResult, AdminRespondToAuthChallengeResult, AuthenticationResultType, ChallengeNameType}

import scala.concurrent.duration.{Duration, DurationInt}

case class TokenBundle(idToken: RawIDToken,
                       accessToken: RawAccessToken,
                       refreshToken: RefreshToken,
                       expiry: Duration) extends Tokens

case class AuthTokens(idToken: RawIDToken,
                      accessToken: RawAccessToken,
                      expiry: Duration) extends Tokens

trait Tokens {
  def accessToken: RawAccessToken

  def idToken: RawIDToken

  def expiry: Duration
}

case class AuthResult(authResult: Option[AuthenticationResultType],
                      challenge: Option[ChallengeNameType],
                      session: String)

object AuthResult {
  def apply(auth: AdminInitiateAuthResult): AuthResult = AuthResult(
    Option(auth.getAuthenticationResult),
    Option(auth.getChallengeName).map(ChallengeNameType.fromValue),
    auth.getSession
  )

  def apply(response: AdminRespondToAuthChallengeResult): AuthResult = AuthResult(
    Option(response.getAuthenticationResult),
    Option(response.getChallengeName).map(ChallengeNameType.fromValue),
    response.getSession
  )
}

object Tokens {
  def bundle(result: AdminInitiateAuthResult): Either[CognitoError, TokenBundle] =
    from(AuthResult(result), fromAuth)

  def refresh(result: AdminInitiateAuthResult): Either[CognitoError, AuthTokens] =
    from(AuthResult(result), fromResult)

  def fromResponse(result: AdminRespondToAuthChallengeResult): Either[CognitoError, TokenBundle] =
    from(AuthResult(result), fromAuth)

  def fromAuth(result: AuthenticationResultType): Either[AuthResultFailure, TokenBundle] =
    for {
      tokens <- fromResult(result).right
      refresh <- mustExist(result.getRefreshToken, "refresh token", result)
    } yield TokenBundle(
      tokens.idToken,
      tokens.accessToken,
      RefreshToken(refresh),
      tokens.expiry
    )

  def fromResult(result: AuthenticationResultType): Either[AuthResultFailure, AuthTokens] =
    for {
      id <- mustExist(result.getIdToken, "id token", result)
      access <- mustExist(result.getAccessToken, "access token", result)
    } yield AuthTokens(
      RawIDToken(id),
      RawAccessToken(access),
      result.getExpiresIn.toInt.seconds
    )

  private def from[T](result: AuthResult,
                      parse: AuthenticationResultType => Either[CognitoError, T]): Either[CognitoError, T] =
    result.authResult
      .toRight(result.challenge
        .map(chal => Challenge(chal, result))
        .getOrElse(CognitoDataMissing("Missing both authentication result and challenge.")))
      .right.flatMap(parse)

  private def mustExist[T](nullable: => T, failInfo: String, result: AuthenticationResultType) =
    Utils.mustExist(nullable, AuthResultFailure(failInfo, result))
}
