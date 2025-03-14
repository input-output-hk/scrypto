import sbt.Keys.{homepage, scalaVersion}

name := "scrypto"
description := "Cryptographic primitives for Scala"
organization := "org.scorexfoundation"

lazy val scala211 = "2.11.12"
lazy val scala212 = "2.12.20"
lazy val scala213 = "2.13.16"
lazy val scala3   = "3.3.5"
lazy val scalatestVersion = "3.2.19"

javacOptions ++=
  "-source" :: "1.8" ::
    "-target" :: "1.8" ::
    Nil

lazy val commonSettings = Seq(
  organization := "org.scorexfoundation",
  resolvers ++= Resolver.sonatypeOssRepos("public"),
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
  libraryDependencies ++= {
    val base = Seq(
      "org.scorexfoundation" %%% "scorex-util" % "0.2.2",
      "org.scalatest" %%% "scalatest" % scalatestVersion % Test,
      "org.scalatest" %%% "scalatest-propspec" % scalatestVersion % Test,
      "org.scalatest" %%% "scalatest-shouldmatchers" % scalatestVersion % Test,
    )
    val supertagged = Seq("org.rudogma" %%% "supertagged" % "2.0-RC2")
    val scalacheck211 = Seq(
      "org.scalatestplus" %%% "scalacheck-1-15" % "3.2.4.0-M1" % Test,
      "org.scalacheck" %%% "scalacheck" % "1.15.2" % Test
    )
    val scalacheckLatest = Seq(
      "org.scalatestplus" %%% "scalacheck-1-18" % "3.2.19.0" % Test,
      "org.scalacheck" %%% "scalacheck" % "1.18.1" % Test
    )

    if (scalaVersion.value == scala211)
      base ++ supertagged ++ scalacheck211
    else if (scalaVersion.value == scala212 | scalaVersion.value == scala213)
      base ++ supertagged ++ scalacheckLatest
    else if (scalaVersion.value == scala3)
      base ++ scalacheckLatest
    else 
      Seq()
  },
  javacOptions ++= javacReleaseOption,
  publishMavenStyle := true,
  publishTo := sonatypePublishToBundle.value
)


Test / publishArtifact := false


pomIncludeRepository := { _ => false }

lazy val noPublishSettings = Seq(
  publish := {},
  publishLocal := {},
  publishArtifact := false
)

lazy val scrypto = crossProject(JVMPlatform, JSPlatform)
    .in(file("."))
    .settings(commonSettings)
    .jvmSettings(
      libraryDependencies ++= Seq(
        "org.bouncycastle" % "bcprov-jdk15to18" % "1.80"
      ),
      scalaVersion := scala213,
      crossScalaVersions := Seq(scala211, scala212, scala213, scala3)
    )

lazy val scryptoJS = scrypto.js
    .enablePlugins(ScalaJSBundlerPlugin)
    .enablePlugins(ScalablyTypedConverterGenSourcePlugin)
    .settings(
      scalaVersion := scala213,
      crossScalaVersions := Seq(scala213, scala3),
      libraryDependencies ++= Seq(
        "org.scala-js" %%% "scala-js-macrotask-executor" % "1.1.1",
        ("org.scala-js" %%% "scalajs-java-securerandom" % "1.0.0").cross(CrossVersion.for3Use2_13)
      ),
      Test / parallelExecution := false,
      // how to setup ScalablyTyped https://scalablytyped.org/docs/library-developer
      stOutputPackage := "scorex",
      Compile / npmDependencies ++= Seq(
        "@noble/hashes" -> "1.6.0"
      ),
      useYarn := false
    )

lazy val benchmarks = project
    .in(file("benchmarks"))
    .dependsOn(scrypto.jvm)
    .settings(
      moduleName := "scrypto-benchmarks",
      crossScalaVersions := Seq(scala211, scala212, scala213, scala3),
      scalaVersion := scala213,
    )
    .enablePlugins(JmhPlugin)
    .settings(noPublishSettings)

def javacReleaseOption = {
  if (System.getProperty("java.version").startsWith("1."))
  // java <9 "--release" is not supported
    Seq()
  else
    Seq("--release", "8")
}

credentials ++= (for {
  username <- Option(System.getenv().get("SONATYPE_USERNAME"))
  password <- Option(System.getenv().get("SONATYPE_PASSWORD"))
} yield Credentials("Sonatype Nexus Repository Manager", "oss.sonatype.org", username, password)).toSeq

// prefix version with "-SNAPSHOT" for builds without a git tag
ThisBuild / dynverSonatypeSnapshots := true
// use "-" instead of default "+"
ThisBuild / dynverSeparator := "-"

// PGP key for signing a release build published to sonatype
// signing is done by sbt-pgp plugin
// how to generate a key - https://central.sonatype.org/pages/working-with-pgp-signatures.html
// how to export a key see ci/import_gpg.sh
pgpPublicRing := file("ci/pubring.asc")
pgpSecretRing := file("ci/secring.asc")
pgpPassphrase := sys.env.get("PGP_PASSPHRASE").map(_.toArray)
usePgpKeyHex("AA4F785C04B9DCCDD5332FB1329014D11A57FA1A")
