package com.malliina.aws.cognito

import java.security.KeyPairGenerator
import java.security.interfaces.{RSAPrivateKey, RSAPublicKey}
import java.util.Date

import com.nimbusds.jose.crypto.{RSASSASigner, RSASSAVerifier}
import com.nimbusds.jose.{JWSAlgorithm, JWSHeader}
import com.nimbusds.jwt.{JWTClaimsSet, SignedJWT}
import org.scalatest.FunSuite

class SignatureTests extends FunSuite {
  val RSA = "RSA"
  val gen = KeyPairGenerator.getInstance(RSA)
  gen initialize 1024
  val pair = gen.generateKeyPair()
  val publicKey = pair.getPublic.asInstanceOf[RSAPublicKey]
  val privateKey = pair.getPrivate.asInstanceOf[RSAPrivateKey]
  val expectedSubject = "alice"
  val expectedIssuer = "https://c2id.com"
  val testKeyId = Key("my-id")
  val testIssuer = Issuer("test-issuer")
  val testVerifier = new TokenVerifier(Seq(PubKey(testKeyId, publicKey)), testIssuer)

  test("can sign and verify") {
    // Sign with private key
    val encoded = signToken(identity, _.subject(expectedSubject).issuer(expectedIssuer))

    // Read with public key
    val jwt = SignedJWT.parse(encoded.token)
    val verifier = new RSASSAVerifier(publicKey)
    assert(jwt verify verifier)
    assert(jwt.getJWTClaimsSet.getSubject === expectedSubject)
    assert(jwt.getJWTClaimsSet.getIssuer === expectedIssuer)
  }

  test("missing issuer") {
    val token = signToken(identity, identity)
    assert(ParsedToken.parse(token).left.get === DataMissing("issuer"))
  }

  test("missing token_use") {
    val token = signToken(identity, _.issuer("anyone"))
    val parsed = ParsedToken.parse(token)
    assert(parsed.isLeft)
    assert(parsed.left.get === DataMissing(ParsedToken.TokenUse))
  }

  test("parsing does not perform validation") {
    // The token_use value validity is only checked when verifying, not parsing
    val expectedTokenUse = "hah"
    val token = signToken(_.keyID("testkid"), cs =>
      cs.issuer(expectedIssuer)
        .claim(ParsedToken.TokenUse, expectedTokenUse)
        .expirationTime(new Date(new Date().getTime - 1000)))
    val parsed = ParsedToken.parse(token)
    assert(parsed.isRight)
    assert(parsed.right.get.tokenUse === expectedTokenUse)
  }

  test("invalid issuer") {
    val issuer = Issuer("yours")
    val result = testVerify(iss = issuer.iss)
    assert(result.left.get === IssuerMismatch(issuer, testVerifier.expectedIssuer))
  }

  test("missing public key") {
    val result = testVerify(keyId = "testkid")
    assert(result.left.get.isInstanceOf[UnknownPublicKey])
  }

  test("expired token fails verification") {
    val result = testVerify(new Date(new Date().getTime - 10000))
    assert(result.left.get.isInstanceOf[TokenExpired])
  }

  test("valid token verifies") {
    val res = testVerify()
    assert(res.isRight)
  }

  def testVerify(exp: Date = new Date(new Date().getTime + 10000),
                 keyId: String = testKeyId.id,
                 iss: String = testIssuer.iss,
                 tokenUse: String = "id") = {
    val token = signToken(_.keyID(keyId), cs => {
      cs.issuer(iss)
        .claim(ParsedToken.TokenUse, tokenUse)
        .expirationTime(exp)
    })
    testVerifier verify token
  }

  def signToken(h: JWSHeader.Builder => JWSHeader.Builder,
                f: JWTClaimsSet.Builder => JWTClaimsSet.Builder): RawToken = {
    val signer = new RSASSASigner(privateKey)
    val header = h(new JWSHeader.Builder(JWSAlgorithm.RS256)).build()
    val claims = f(new JWTClaimsSet.Builder()).build()
    val token = new SignedJWT(header, claims)
    token sign signer
    RawAccessToken(token.serialize())
  }
}
