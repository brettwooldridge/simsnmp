#!/usr/bin/env bash

/usr/bin/java -Dhandler=./load-agent.js -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:8887 -jar /root/sim/simsnmp-all.jar
