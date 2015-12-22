name := "scrypto"

version := "1.0.0"

scalaVersion := "2.11.7"


libraryDependencies ++= Seq(
  "io.spray" %% "spray-testkit" % "1.+" % "test",
  "org.scalatest" %% "scalatest" % "2.+" % "test",
  "org.scalactic" %% "scalactic" % "2.+" % "test",
  "org.scalacheck" %% "scalacheck" % "1.+" % "test",
  "org.whispersystems" % "curve25519-java" % "+",
  "commons-net" % "commons-net" % "3.+"
)