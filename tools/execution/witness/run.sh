#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64
export JAVA_HOME PATH="$JAVA_HOME/bin:/usr/bin:/bin" LANG=C LC_ALL=C TZ=UTC
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cat >"$WORK/classpath.gradle" <<'GRADLE'
allprojects { p ->
  if (p.path == ':framework') { p.afterEvaluate {
    p.tasks.register('c012WitnessRuntimeClasspath') { doLast { println p.sourceSets.test.runtimeClasspath.asPath } }
  } }
}
GRADLE
cd "$ROOT/java-tron"
./gradlew --no-daemon --no-build-cache --console=plain --dependency-verification=strict -I "$WORK/classpath.gradle" :framework:testClasses >/dev/null
CP=$(./gradlew --no-daemon --no-build-cache --console=plain --dependency-verification=strict -I "$WORK/classpath.gradle" -q :framework:c012WitnessRuntimeClasspath | sed -n '/:/p' | tail -n 1)
mkdir "$WORK/classes"
"$JAVA_HOME/bin/javac" -encoding UTF-8 -source 8 -target 8 -cp "$CP" -d "$WORK/classes" "$ROOT/tools/execution/witness/C012WitnessOracle.java"
cd "$ROOT"
"$JAVA_HOME/bin/java" -Duser.timezone=UTC -Dfile.encoding=UTF-8 -cp "$WORK/classes:$CP" org.tron.core.actuator.C012WitnessOracle "$ROOT/docs/oracles/c012-witness-real.v1.json"
