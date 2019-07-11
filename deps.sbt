val playVersion = "2.6.12"

val testDependencies = Seq(
  "org.scalatest" %% "scalatest" % "3.0.5" % Test
)

libraryDependencies ++= Seq(
  "com.typesafe.play"    %% "play-ws"             % playVersion,
  "ohnosequences"        %% "webapp-db-postgrest" % "0.1.2",
  "org.abstractj.kalium" % "kalium"               % "0.8.0"
) ++ testDependencies
