#!/usr/bin/env ash
set -e

main(){
	if [ ! "$1" ]; then
		showHelp
		exit 1
	fi

	if ! go env GOPATH > /dev/null; then
		echo "Could not find GOPATH."
		echo "Please install go: https://golang.org/doc/install"
		exit 1
	fi
	gopath="$(go env GOPATH)"

	if ! echo $PATH | grep -q $gopath/bin; then
		echo "Please add '$gopath/bin' to your '$PATH'"
		PATH=$PATH:$gopath/bin
		export PATH
	fi

	if [ ! "$IP" ]; then
		echo "Please set the IP env variable."
		exit 1
	fi

	if [ ! "$PORTBASE" ]; then
		echo "Please set the PORTBASE env variable."
		exit 1
	fi
	
	runLocal $@
}

showHelp(){
		cat - <<EOF
Syntax is $0 nbr [dbg_lvl]	# runs nbr local conodes - you can give a debug-level as second
					# argument: 1-sparse..5-flood.
EOF
}

runLocal(){
	NBR=$1
	WAIT="yes"
	DEBUG=3
	if [ "$2" ]; then
		DEBUG=$2
	fi
	local BUILD=true

	rm -v public.toml 2> /dev/null || true
	for n in $( seq $NBR ); do
		co=co$n
		# if not present, setup
		if [ ! -d $co ]; then
			echo -e "$IP:$(($PORTBASE + 2 * $n))\nConode_$n\n$co" | conode setup
		fi
		# start
		conode -d $DEBUG -c $co/private.toml server &
		cat $co/public.toml >> public.toml
	done
	sleep 1

	cat - <<EOF

*********

Now you can use public.toml as the group-toml file to interact with your
local cothority.
EOF

	if [ "$WAIT" ]; then
		echo -e "\nWaiting for <ctrl-c>"
		while sleep 3600; do
			date
		done
	fi
}

main $@
