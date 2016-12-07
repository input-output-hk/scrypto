organization := "org.consensusresearch"

name := "scrypto"

version := "1.2.0-RC3"

scalaVersion := "2.12.1"

libraryDependencies ++= Seq(
  "com.chuusai" %% "shapeless" % "2.+",
  "com.google.guava" % "guava" % "19.+",
  "org.mapdb" % "mapdb" % "3.+" % "test",
  "org.scalatest" %% "scalatest" % "3.+" % "test",
  "org.scalacheck" %% "scalacheck" % "1.13.+" % "test",
  "org.slf4j" % "slf4j-api" % "1.+",
  "org.whispersystems" % "curve25519-java" % "+"
)
scalacOptions ++= Seq("-Xdisable-assertions")

licenses := Seq("CC0" -> url("https://creativecommons.org/publicdomain/zero/1.0/legalcode"))

homepage := Some(url("https://github.com/ScorexProject/scrypto"))

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


mainClass in assembly := Some("perf.PerformanceMeter")