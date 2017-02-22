package com.malliina.aws

import scala.concurrent.Future

package object cognito {
  def fut[T](t: T): Future[T] = Future.successful(t)
}
