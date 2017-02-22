package com.malliina.aws.cognito

import java.security.interfaces.RSAPublicKey
import java.util.Date

import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jwt.SignedJWT

case class AccessToken private(username: Username,
                               clientId: App,
                               sub: String,
                               v: VerifiedToken)
  extends VerifiedToken(v)

object AccessToken {
  def fromRaw(accessToken: RawAccessToken, verifier: Verifier): Either[JWTError, AccessToken] =
    verifier verifyAccess accessToken
}

case class IdToken private(sub: String, aud: Seq[String], v: VerifiedToken)
  extends VerifiedToken(v)

object IdToken {
  def fromRaw(idToken: RawIDToken, verifier: Verifier): Either[JWTError, IdToken] =
    verifier verifyId idToken
}

class VerifiedToken private(val issuer: Issuer,
                            val tokenUse: String,
                            val key: Key,
                            val expiration: Date,
                            val signed: SignedJWT) extends JWT {
  def this(v: VerifiedToken) = this(v.issuer, v.tokenUse, v.key, v.expiration, v.signed)
}

object VerifiedToken {
  val Id = "id"
  val Access = "access"
  val TokenUseValues = Seq(Id, Access)

  /** Verifies `jwt`. See the linked URL for details.
    *
    * Decode the token string into JWT format.
    * Check the iss claim. It should match your user pool.
    * Check the token_use claim.
    * Get the kid from the JWT token header and retrieve the corresponding JSON Web Key.
    * Verify the signature of the decoded JWT token.
    * Check the exp claim and make sure the token is not expired.
    * You can now trust the claims inside the token and use it as it fits your requirements.
    *
    * @param jwt            a parsed token
    * @param expectedIssuer the expected issuer
    * @param keys           public keys
    * @return a verified token iff it can be trusted or an error otherwise
    * @see http://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html
    */
  def verify(jwt: JWT, expectedIssuer: Issuer, keys: Seq[PubKey]): Either[JWTError, VerifiedToken] =
    for {
      _ <- validateIssuer(jwt.issuer, expectedIssuer).right
      _ <- validateTokenUse(jwt.tokenUse).right
      pubKey <- findPublicKey(jwt, keys).right
      _ <- verifySignature(jwt, pubKey.publicKey).right
      _ <- checkExpiration(jwt.expiration).right
    } yield new VerifiedToken(jwt.issuer, jwt.tokenUse, jwt.key, jwt.expiration, jwt.signed)

  // Verification helpers

  private def validateIssuer(actual: Issuer, expected: Issuer) =
    if (actual == expected) Right(actual)
    else Left(IssuerMismatch(actual, expected))

  private def findPublicKey(jwt: JWT, keys: Seq[PubKey]): Either[UnknownPublicKey, PubKey] = {
    val keyId = jwt.key
    keys.find(_.id == keyId).toRight(UnknownPublicKey(keyId))
  }

  private def verifySignature(jwt: JWT, publicKey: RSAPublicKey): Either[VerifyError, Unit] = {
    val verifier = new RSASSAVerifier(publicKey)
    val isValid = jwt.signed verify verifier
    if (isValid) Right(())
    else Left(VerifyError(jwt.key))
  }

  private def checkExpiration(expiration: Date): Either[TokenExpired, Unit] =
    if (isExpired(expiration, new Date)) Left(TokenExpired(expiration))
    else Right(())

  private def isExpired(expiration: Date, now: Date): Boolean =
    now.compareTo(expiration) > 0

  private def validateTokenUse(tokenUse: String) =
    if (TokenUseValues contains tokenUse) Right(tokenUse)
    else Left(JWTError.unknownTokenUse(tokenUse))
}
