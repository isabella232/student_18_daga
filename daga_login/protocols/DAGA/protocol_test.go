package DAGA_test

import (
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/student_18_daga/daga_login"
	"github.com/dedis/student_18_daga/daga_login/protocols/DAGA"
	protocols_testing "github.com/dedis/student_18_daga/daga_login/protocols/testing"
	"github.com/dedis/student_18_daga/sign/daga"
	"github.com/stretchr/testify/require"
	"testing"
)

var tSuite = daga.NewSuiteEC()

func TestMain(m *testing.M) {
	log.MainTest(m)
}

// Tests a 2, 5 and 13-node system. (complete protocol run)
func TestServerProtocol(t *testing.T) {
	nodes := []int{2, 5, 13}
	for _, nbrNodes := range nodes {
		runProtocol(t, nbrNodes)
	}
}

func runProtocol(t *testing.T, nbrNodes int) {
	log.Lvl2("Running", DAGA.Name, "with", nbrNodes, "nodes")
	local := onet.NewLocalTest(tSuite)
	defer local.CloseAll()

	services, dummyRequest, dummyContext := protocols_testing.ValidServiceSetup(local, nbrNodes)

	// create and setup root protocol instance + start protocol
	netRequest := daga_login.NetEncodeAuthenticationMessage(*dummyContext, *dummyRequest)
	dagaProtocol := services[0].(*protocols_testing.DummyService).NewDAGAServerProtocol(t, *netRequest)

	serverMsg, err := dagaProtocol.WaitForResult()
	require.NoError(t, err, "failed to get result of protocol run")
	require.NotZero(t, serverMsg)

	// verify / extract tag
	Tf, err := daga.GetFinalLinkageTag(tSuite, dummyContext, serverMsg)
	require.NoError(t, err, "failed to extract tag from the resulting serverMsg")
	require.NotZero(t, Tf)
}