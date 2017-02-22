package com.malliina.aws.cognito

import java.nio.file.{Files, Paths}

import com.amazonaws.regions.Regions
import com.amazonaws.services.cognitoidp.model._
import com.typesafe.config.ConfigFactory
import org.scalatest.BeforeAndAfterAll

import scala.collection.JavaConversions.asScalaBuffer

class CognitoTests extends BaseSuite with BeforeAndAfterAll {
  val confFile = Paths.get(sys.props("user.home")).resolve(".aws").resolve("cognito.conf")
  val conf = ConfigFactory.parseFile(confFile.toFile)
  lazy val userPool = UserPool(conf getString "userPool")
  lazy val app = App(conf getString "app")
  lazy val email = conf getString "email"
  lazy val cognito = Cognito(Regions.EU_WEST_1, userPool, app)
  lazy val verifier = TokenVerifier.forUserPool(Regions.EU_WEST_1, userPool)

  val testUser = Username("demo123")
  val tempPass = Password("temppass")
  val testPass = Password("passdemo")

  override protected def beforeAll() = {
    if (Files.exists(confFile)) {
      cognito.removeUser(testUser)
      cognito.createUser(testUser, tempPass, testPass, email)
    }

  }

  override protected def afterAll() = {
    if (Files.exists(confFile)) {
      cognito.removeUser(testUser)
    }
  }

  ignore("list users") {
    val listUsersReq = new ListUsersRequest
    listUsersReq setUserPoolId userPool.id
    val usersList = cognito.client listUsers listUsersReq
    val usernames = usersList.getUsers.map(u => Username(u.getUsername))
    assert(usernames contains testUser)
  }

  ignore("create-delete user") {
    val doomedUser = Username("temp1234")
    val doomedPass = Password("pass2345")
    val res = cognito.createUser(doomedUser, Password("pass1234"), doomedPass, email)
    assert(res.isRight)
    val res2 = cognito.removeUser(doomedUser)
    assert(res2.isRight)
  }

  ignore("first login") {
    val res = cognito.firstLogin(Username("du"), Password("DRXaLMU"), Password("mypass123"), email)
    println(res)
  }

  ignore("authenticate") {
    val res = cognito.authenticate(testUser, testPass)
    assert(res.isRight)
  }

  ignore("authenticateAsync") {
    val tokens = await(cognito.authenticateAsync(testUser, testPass))
    assert(tokens.right.get.accessToken.token.nonEmpty)
  }

  ignore("get refresh token") {
    val tokens = await(cognito.authenticateAsync(testUser, testPass))
    val refreshToken = tokens.right.get.refreshToken
    val refreshed = await(cognito.refreshAsync(testUser, refreshToken))
    assert(refreshed.isRight)
  }

  ignore("verify token") {
    // http://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html
    val tokens = cognito.authenticate(testUser, testPass).right.get
    val result = verifier verify tokens.idToken
    assert(result.isRight)
  }

  ignore("get access token") {
    val tokens = await(cognito.authenticateAsync(testUser, testPass)).right.get
    val result = AccessToken.fromRaw(tokens.accessToken, verifier)
    assert(result.isRight)
    val token = result.right.get
    assert(token.username === testUser)
    assert(token.clientId === app)
  }

  ignore("get id token") {
    val tokens = await(cognito.authenticateAsync(testUser, testPass)).right.get
    val result = IdToken.fromRaw(tokens.idToken, verifier)
    assert(result.isRight)
    val token = result.right.get
    assert(token.aud.exists(aud => App(aud) === app))
  }

}
