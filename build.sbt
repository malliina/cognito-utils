import com.malliina.sbtutils.SbtProjects

lazy val p = SbtProjects.testableProject("cognito-utils")

version := "0.0.1"

scalaVersion := "2.11.8"

libraryDependencies ++= Seq(
  "com.amazonaws" % "aws-java-sdk" % "1.11.89",
  "com.nimbusds" % "nimbus-jose-jwt" % "4.23",
  "org.apache.httpcomponents" % "httpclient" % "4.5.3",
  "com.typesafe.play" %% "play-json" % "2.5.12"
)
