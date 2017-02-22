package com.malliina.aws.cognito

import scala.util.Either.RightProjection

object Utils {
  def mustExist[F, T](nullable: => T, failInfo: => F): RightProjection[F, T] =
    Option(nullable).toRight[F](failInfo).right
}
