organization := "org.scorexfoundation"

name := "scrypto"

version := "2.0.0"

scalaVersion := "2.12.3"

crossScalaVersions := Seq("2.11.11", "2.12.3")

libraryDependencies ++= Seq(
  "org.rudogma" %% "supertagged" % "1.+",
  "com.google.guava" % "guava" % "19.+",
  "org.slf4j" % "slf4j-api" % "1.7.+",
  "org.whispersystems" % "curve25519-java" % "+",
  "org.bouncycastle" % "bcprov-jdk15on" % "1.58"
)

libraryDependencies ++= Seq(
  "org.scalatest" %% "scalatest" % "3.0.+" % "test",
  "org.scalacheck" %% "scalacheck" % "1.13.+" % "test",
  "com.storm-enroute" %% "scalameter" % "0.8.2" % "test"
)

testFrameworks += new TestFramework("org.scalameter.ScalaMeterFramework")

parallelExecution in Test := false

licenses := Seq("CC0" -> url("https://creativecommons.org/publicdomain/zero/1.0/legalcode"))

homepage := Some(url("https://github.com/input-output-hk/scrypto"))

publishMavenStyle := true

publishArtifact in Test := false

publishTo := {
  val nexus = "https://oss.sonatype.org/"
  if (isSnapshot.value) Some("snapshots" at nexus + "content/repositories/snapshots")
  else Some("releases"  at nexus + "service/local/staging/deploy/maven2")
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