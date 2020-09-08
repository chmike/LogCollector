Running the logCollector:

    cd ~/go/src/logCollector
    logCollector -s -a 0.0.0.0:3001 -logstash 134.158.21.55:3003  -cas cas.pem

Running the logSserver:

    cd ~/go/src/logServer
    source esconfig.sh
    logServer