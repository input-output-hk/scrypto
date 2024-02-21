
logLevel := Level.Warn

addSbtPlugin("com.jsuereth" % "sbt-pgp" % "2.0.0")

//addSbtPlugin("org.scalastyle" %% "scalastyle-sbt-plugin" % "1.0.0")

//addSbtPlugin("org.scoverage" % "sbt-scoverage" % "1.3.5")

addSbtPlugin("pl.project13.scala" % "sbt-jmh" % "0.3.3")

addSbtPlugin("org.xerial.sbt" % "sbt-sonatype" % "3.8")

addSbtPlugin("net.virtual-void" % "sbt-dependency-graph" % "0.9.0")

addSbtPlugin("com.dwijnand" % "sbt-dynver" % "4.1.1")

addSbtPlugin("org.portable-scala" % "sbt-scalajs-crossproject" % "1.2.0")
addSbtPlugin("org.scala-js"       % "sbt-scalajs"              % "1.10.1")
addSbtPlugin("ch.epfl.scala"      % "sbt-scalajs-bundler"      % "0.20.0")
addSbtPlugin("org.scalablytyped.converter" % "sbt-converter" % "1.0.0-beta43")