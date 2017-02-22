package com.malliina.aws.cognito

import java.util.concurrent.Executors

import com.amazonaws.AmazonWebServiceRequest
import com.amazonaws.handlers.AsyncHandler
import com.amazonaws.regions.Regions
import com.amazonaws.services.cognitoidp.model._
import com.amazonaws.services.cognitoidp.{AWSCognitoIdentityProviderAsyncClientBuilder, AWSCognitoIdentityProviderClientBuilder}
import com.malliina.aws.cognito.Cognito._

import scala.collection.JavaConversions.mapAsJavaMap
import scala.concurrent.{ExecutionContext, Future, Promise}
import scala.util.{Failure, Success, Try}

object Cognito {
  val NewPasswordKey = "NEW_PASSWORD"
  val NewPasswordRequired = "NEW_PASSWORD_REQUIRED"
  val PasswordKey = "PASSWORD"
  val RefreshTokenKey = "REFRESH_TOKEN"
  val UsernameKey = "USERNAME"
  val EmailAttribute = "userAttributes.email"

  def apply(region: Regions, pool: UserPool, appId: App): Cognito =
    new Cognito(region, pool, appId, cachedExecutionContext())

  // Does the thread pool need to be shut down on exit?
  def cachedExecutionContext(): ExecutionContext =
    ExecutionContext.fromExecutorService(Executors.newCachedThreadPool())

  implicit class TryOps[T](t: Try[T]) {
    def fold[X](success: T => X, failure: Throwable => X): X = t match {
      case Success(s) => success(s)
      case Failure(err) => failure(err)
    }
  }

}

class Cognito(region: Regions, userPool: UserPool, app: App, ec: ExecutionContext) {
  implicit val exec = ec
  val client = AWSCognitoIdentityProviderClientBuilder.standard()
    .withRegion(region)
    .build()
  val asyncClient = AWSCognitoIdentityProviderAsyncClientBuilder.standard()
    .withRegion(region)
    .build()

  def authenticateAsync(user: Username, pass: Password): Future[Either[CognitoError, TokenBundle]] =
    makeAuthRequest(buildAuthRequest(user, pass), Tokens.bundle)

  def authenticate(user: Username, pass: Password): Either[CognitoError, TokenBundle] =
    for {
      response <- withCognito(client adminInitiateAuth buildAuthRequest(user, pass)).right
      tokens <- Tokens.bundle(response).right
    } yield tokens

  def refreshAsync(user: Username, refreshToken: RefreshToken): Future[Either[CognitoError, AuthTokens]] =
    makeAuthRequest(refreshRequest(user, refreshToken), Tokens.refresh)

  def respondAsync(user: Username,
                   challenge: ChallengeNameType,
                   session: String,
                   authParams: Map[String, String]): Future[Either[CognitoError, AdminRespondToAuthChallengeResult]] = {
    val req = buildRespondReq(user, challenge, session, authParams)
    makeRequest(asyncClient.adminRespondToAuthChallengeAsync)(req)
  }

  def firstLogin(user: Username, tempPass: Password, pass: Password, email: String): Either[CognitoError, TokenBundle] = {
    authenticate(user, tempPass).left.flatMap {
      {
        case Challenge(name, result) if name == ChallengeNameType.NEW_PASSWORD_REQUIRED =>
          respondNewPassword(user, result.session, pass, email).right.flatMap(r => Tokens.fromResponse(r))
        case other =>
          Left(other)
      }
    }
  }

  def createUser(user: Username, tempPass: Password, pass: Password, email: String): Either[CognitoError, TokenBundle] =
    for {
      _ <- createUser(user, tempPass).right
      tokens <- firstLogin(user, tempPass, pass, email).right
    } yield tokens

  def createUser(user: Username, tempPass: Password): Either[CognitoException, AdminCreateUserResult] = {
    val req = new AdminCreateUserRequest()
      .withUsername(user.user)
      .withTemporaryPassword(tempPass.pass)
      .withUserPoolId(userPool.id)
    withCognito(client adminCreateUser req)
  }

  def removeUser(user: Username): Either[CognitoException, AdminDeleteUserResult] = {
    val req = new AdminDeleteUserRequest()
      .withUsername(user.user)
      .withUserPoolId(userPool.id)
    withCognito(client adminDeleteUser req)
  }

  def respondNewPassword(user: Username,
                         session: String,
                         newPassword: Password,
                         email: String) = {
    val params = Map(NewPasswordKey -> newPassword.pass, EmailAttribute -> email)
    val req = buildRespondReq(user, ChallengeNameType.NEW_PASSWORD_REQUIRED, session, params)
    withCognito(client adminRespondToAuthChallenge req)
  }

  def respond(user: Username,
              challenge: ChallengeNameType,
              session: String,
              authParams: Map[String, String]): Either[CognitoException, AdminRespondToAuthChallengeResult] = {
    val req = buildRespondReq(user, challenge, session, authParams)
    withCognito(client adminRespondToAuthChallenge req)
  }

  private def buildRespondReq(user: Username,
                              challenge: ChallengeNameType,
                              session: String,
                              authParams: Map[String, String]) =
    new AdminRespondToAuthChallengeRequest()
      .withChallengeName(challenge)
      .withChallengeResponses(Map(UsernameKey -> user.user) ++ authParams)
      .withClientId(app.id)
      .withSession(session)
      .withUserPoolId(userPool.id)

  private def refreshRequest(user: Username, refreshToken: RefreshToken) =
    adminAuthRequest(
      AuthFlowType.REFRESH_TOKEN_AUTH,
      Map(UsernameKey -> user.user, RefreshTokenKey -> refreshToken.token)
    )

  private def buildAuthRequest(user: Username, pass: Password): AdminInitiateAuthRequest =
    adminAuthRequest(
      AuthFlowType.ADMIN_NO_SRP_AUTH,
      Map(UsernameKey -> user.user, PasswordKey -> pass.pass)
    )

  private def adminAuthRequest(authFlow: AuthFlowType, authParams: Map[String, String]) =
    new AdminInitiateAuthRequest()
      .withAuthFlow(authFlow)
      .withAuthParameters(authParams)
      .withClientId(app.id)
      .withUserPoolId(userPool.id)

  private def makeAuthRequest[T](request: AdminInitiateAuthRequest,
                                 parse: AdminInitiateAuthResult => Either[CognitoError, T]): Future[Either[CognitoError, T]] = {
    val result = makeRequest(asyncClient.adminInitiateAuthAsync)(request)
    result.map(res => res.right.flatMap(parse))
  }

  /** This unconventional method signature is designed to minimize
    * the need for type annotations at call-site.
    */
  private def makeRequest[Req <: AmazonWebServiceRequest, Res](start: (Req, AsyncHandler[Req, Res]) => Any)(req: Req): Future[Either[CognitoException, Res]] = {
    val p = Promise[Either[CognitoException, Res]]()
    val handler = new AsyncHandler[Req, Res] {
      override def onError(exception: Exception) = exception match {
        case cognito: AWSCognitoIdentityProviderException => p.success(Left(CognitoException(cognito)))
        case other => p.failure(other)
      }

      override def onSuccess(request: Req, result: Res) = p.success(Right(result))
    }
    start(req, handler)
    p.future
  }

  private def withCognito[T](code: => T): Either[CognitoException, T] =
    try {
      Right(code)
    } catch {
      case awsErr: AWSCognitoIdentityProviderException =>
        Left(CognitoException(awsErr))
    }
}
