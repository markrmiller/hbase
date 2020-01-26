
#!/usr/bin/env bash

mvn clean
mvn install -DskipTests

mvn -T $1 -Dsurefire.firstPartForkCount=$1 -Dsurefire.secondPartForkCount=$1 test
