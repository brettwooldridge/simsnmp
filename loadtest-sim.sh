#!/usr/bin/env bash

/usr/bin/java -Djava.security.egd=file:/dev/./urandom -Dhandler=./load-agent.js -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:8887 -jar /root/sim/simsnmp-all.jar
