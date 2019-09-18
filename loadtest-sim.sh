#!/usr/bin/env bash

/usr/bin/java -Djava.security.egd=file:/dev/./urandom -Dhandler=./load-agent.js -Dlog4j.configurationFile=./log4j2.yaml -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:8887 -jar ./simsnmp-all.jar
