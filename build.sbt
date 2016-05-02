organization := "org.consensusresearch"

name := "scrypto"

version := "1.2.0-M2"

scalaVersion := "2.11.8"

libraryDependencies ++= Seq(
  "com.h2database" % "h2-mvstore" % "1.4.191",
  "com.google.guava" % "guava" % "15.+",
  "com.typesafe.play" %% "play-json" % "2.4.+",
  "io.spray" %% "spray-testkit" % "1.+" % "test",
  "org.scalatest" %% "scalatest" % "2.+" % "test",
  "org.scalactic" %% "scalactic" % "2.+" % "test",
  "org.scalacheck" %% "scalacheck" % "1.12.+" % "test",
  "org.slf4j" % "slf4j-api" % "1.+",
  "org.whispersystems" % "curve25519-java" % "+"
)

licenses := Seq("CC0" -> url("https://creativecommons.org/publicdomain/zero/1.0/legalcode"))

homepage := Some(url("https://github.com/ScorexProject/scrypto"))

resolvers ++= Seq("Sonatype Releases" at "http://oss.sonatype.org/content/repositories/releases/",
  "Typesafe maven releases" at "http://repo.typesafe.com/typesafe/maven-releases/")

publishMavenStyle := true

publishArtifact in Test := false

publishTo := {
  val nexus = "https://oss.sonatype.org/"
  if (isSnapshot.value)
    Some("snapshots" at nexus + "content/repositories/snapshots")
  else
    Some("releases"  at nexus + "service/local/staging/deploy/maven2")
}

pomIncludeRepository := { _ => false }

pomExtra :=
  <scm>
    <url>git@github.com:ScorexProject/scrypto.git</url>
    <connection>scm:git:git@github.com:ScorexProject/scrypto.git</connection>
  </scm>
    <developers>
      <developer>
        <id>kushti</id>
        <name>Alexander Chepurnoy</name>
        <url>http://chepurnoy.org/</url>
      </developer>
    </developers>
