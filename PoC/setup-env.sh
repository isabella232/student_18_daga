#!/bin/bash
# used to hack around the fact that .env file doesn't perform variable expension nor executes shell expressions, interactive config = "bonus"

echo "http listen port of the RP app (default 8080):"
read RPPORT
[ -z "$RPPORT" ] && RPPORT=8080
echo $RPPORT

echo "http listen port of the OP app (default 5556):"
read OPPPORT
[ -z "$OPPORT" ] && OPPORT=5556
echo $OPPORT

echo "docker host ip (in the docker net/as seen from containers, default 172.18.0.1):"
read DOCKER_HOST_IP
[ -z "$DOCKER_HOST_IP" ] && DOCKER_HOST_IP=172.18.0.1
echo $DOCKER_HOST_IP

echo "number of daga nodes to run inside the daga service/container (size of local cothority, default 13):"
read DAGA_NBNODES
[ -z "$DAGA_NBNODES" ] && DAGA_NBNODES=13
echo $DAGA_NBNODES

echo "daga log lvl, default 3):"
read DAGA_LOGLVL
[ -z "$DAGA_LOGLVL" ] && DAGA_LOGLVL=3
echo $DAGA_LOGLVL

echo "daga portbase (the nodes will listen in the range portbase-(portbase + 2 * nbnodes + 1), default 12000):"
read DAGA_PORTBASE
[ -z "$DAGA_PORTBASE" ] && DAGA_PORTBASE=12000
DAGA_PORTRANGE=$DAGA_PORTBASE-$(($DAGA_PORTBASE + 2 * $DAGA_NBNODES + 1))
echo "base: $DAGA_PORTBASE, range: $DAGA_PORTRANGE"

cat >.env <<EOL
RPPORT=$RPPORT
OPPORT=$OPPORT
DOCKER_HOST_IP=$DOCKER_HOST_IP
DAGA_NBNODES=$DAGA_NBNODES
DAGA_LOGLVL=$DAGA_LOGLVL
DAGA_PORTBASE=$DAGA_PORTBASE
DAGA_PORTRANGE=$DAGA_PORTRANGE
EOL


