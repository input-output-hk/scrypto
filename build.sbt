import sbt.Keys.{homepage, scalaVersion}

name := "scrypto"
description := "Cryptographic primitives for Scala"

lazy val scala213 = "2.13.8"
lazy val scala212 = "2.12.15"
lazy val scala211 = "2.11.12"

crossScalaVersions := Seq(scala212, scala211, scala213)
scalaVersion := scala213

javacOptions ++=
  "-source" :: "1.8" ::
    "-target" :: "1.8" ::
    Nil

lazy val commonSettings = Seq(
  organization := "org.scorexfoundation",
  resolvers += Resolver.sonatypeRepo("public"),
  licenses := Seq("CC0" -> url("https://creativecommons.org/publicdomain/zero/1.0/legalcode")),
  homepage := Some(url("https://github.com/input-output-hk/scrypto")),
  pomExtra :=
      <developers>
        <developer>
          <id>kushti</id>
          <name>Alexander Chepurnoy</name>
          <url>http://chepurnoy.org/</url>
        </developer>
      </developers>,
  scmInfo := Some(
      ScmInfo(
          url("https://github.com/input-output-hk/scrypto"),
          "scm:git@github.com:input-output-hk/scrypto.git"
      )
  ),
)

libraryDependencies ++= Seq(
  "org.rudogma" %% "supertagged" % "2.0-RC2",
  "com.typesafe.scala-logging" %% "scala-logging" % "3.9.2",
  "org.bouncycastle" % "bcprov-jdk15to18" % "1.66",
  "org.scorexfoundation" %% "scorex-util" % "0.1.8-18-4f4d3c60-SNAPSHOT"
)

libraryDependencies ++= Seq(
  "org.scalatest" %% "scalatest" % "3.1.+" % Test,
  "org.scalacheck" %% "scalacheck" % "1.14.+" % Test,
  // https://mvnrepository.com/artifact/org.scalatestplus/scalatestplus-scalacheck
  "org.scalatestplus" %% "scalatestplus-scalacheck" % "3.1.0.0-RC2" % Test
)

publishMavenStyle := true

publishArtifact in Test := false

publishTo := sonatypePublishToBundle.value

pomIncludeRepository := { _ => false }

lazy val scrypto = (project in file("."))
    .settings(commonSettings: _*)

//lazy val benchmarks = (project in file("benchmarks"))
//  .settings(commonSettings, name := "scrypto-benchmarks")
//  .dependsOn(scrypto)
//  .enablePlugins(JmhPlugin)

credentials ++= (for {
  username <- Option(System.getenv().get("SONATYPE_USERNAME"))
  password <- Option(System.getenv().get("SONATYPE_PASSWORD"))
} yield Credentials("Sonatype Nexus Repository Manager", "oss.sonatype.org", username, password)).toSeq

// prefix version with "-SNAPSHOT" for builds without a git tag
dynverSonatypeSnapshots in ThisBuild := true
// use "-" instead of default "+"
dynverSeparator in ThisBuild := "-"

// PGP key for signing a release build published to sonatype
// signing is done by sbt-pgp plugin
// how to generate a key - https://central.sonatype.org/pages/working-with-pgp-signatures.html
// how to export a key see ci/import_gpg.sh
pgpPublicRing := file("ci/pubring.asc")
pgpSecretRing := file("ci/secring.asc")
pgpPassphrase := sys.env.get("PGP_PASSPHRASE").map(_.toArray)
usePgpKeyHex("AA4F785C04B9DCCDD5332FB1329014D11A57FA1A")
