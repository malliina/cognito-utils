package com.malliina.aws.cognito

import org.scalatest.FunSuite

import scala.concurrent.duration.{Duration, DurationInt}
import scala.concurrent.{Await, Future}

class BaseSuite extends FunSuite {
  def await[T](f: Future[T], duration: Duration = 10.seconds): T =
    Await.result(f, duration)
}
