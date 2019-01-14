#!/usr/bin/env bash

DBG_TEST=1
# Debug-level for app
DBG_APP=2

. $(go env GOPATH)/src/github.com/dedis/onet/app/libtest.sh

main(){
    startTest
    buildConode
# TODO shell tests.
    stopTest
}

testBuild(){
    testOK dbgRun runTmpl --help
}

runTmpl(){
    dbgRun ./$APP -d $DBG_APP $@
}

main
