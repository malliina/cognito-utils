package com.malliina.aws.cognito

import java.net.URI
import java.nio.charset.StandardCharsets

import com.amazonaws.regions.Regions
import org.apache.http.client.methods.HttpGet
import org.apache.http.impl.client.{CloseableHttpClient, HttpClients}
import org.apache.http.util.EntityUtils
import play.api.libs.json.Json

trait Verifier {
  def verify(token: RawToken): Either[JWTError, VerifiedToken]

  def verifyAccess(token: RawAccessToken): Either[JWTError, AccessToken] =
    verify(token).right.flatMap(JWT.access)

  def verifyId(token: RawIDToken): Either[JWTError, IdToken] =
    verify(token).right.flatMap(JWT.id)
}

class TokenVerifier(publicKeys: Seq[PubKey],
                    val expectedIssuer: Issuer) extends Verifier {
  override def verify(token: RawToken): Either[JWTError, VerifiedToken] =
    JWT.verifyToken(token, expectedIssuer, publicKeys)
}

object TokenVerifier {
  def forUserPool(region: Regions, userPool: UserPool): TokenVerifier = {
    val keySetUri = jwtSet(region, userPool)
    val keys = Json.parse(fetch(keySetUri)).as[JWTKeys].keys map { key =>
      PubKey(key.kid, Keys.publicKey(key))
    }
    val expectedIssuer = Issuer(s"https://cognito-idp.${region.getName}.amazonaws.com/$userPool")
    new TokenVerifier(keys, expectedIssuer)
  }

  protected def jwtSet(region: Regions, userPool: UserPool): URI =
    new URI(s"https://cognito-idp.${region.getName}.amazonaws.com/$userPool/.well-known/jwks.json")

  def fetch(uri: URI): String = {
    val http = HttpClients.createDefault()
    try {
      fetch(http, uri)
    } finally {
      http.close()
    }
  }

  protected def fetch(http: CloseableHttpClient, uri: URI): String = {
    val req = new HttpGet(uri)
    val res = http execute req
    try {
      val entity = res.getEntity
      EntityUtils.toString(entity, StandardCharsets.UTF_8)
    } finally {
      res.close()
    }
  }
}
