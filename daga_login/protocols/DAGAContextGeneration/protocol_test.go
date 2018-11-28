package DAGAContextGeneration_test

import (
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/student_18_daga/daga_login"
	"github.com/dedis/student_18_daga/daga_login/protocols/DAGAContextGeneration"
	protocols_testing "github.com/dedis/student_18_daga/daga_login/testing"
	"github.com/dedis/student_18_daga/sign/daga"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"testing"
)

var tSuite = daga.NewSuiteEC()

func TestMain(m *testing.M) {
	log.MainTest(m)
}

// Tests a 2, 5 and 13-node system. (complete protocol run)
func TestChallengeGeneration(t *testing.T) {
	nodes := []int{2, 5, 13}
	for _, nbrNodes := range nodes {
		runProtocol(t, nbrNodes)
	}
}

// TODO more DRY helpers fair share of code is .. shared..

func runProtocol(t *testing.T, nbrNodes int) {
	log.Lvl2("Running", DAGAContextGeneration.Name, "with", nbrNodes, "nodes")
	local := onet.NewLocalTest(tSuite)
	defer local.CloseAll()

	services, _, _ := protocols_testing.ValidServiceSetup(local, nbrNodes)

	// build roster (QUESTION...no other way to get roster from local ?)
	servers := make([]*onet.Server, 0, len(local.Servers))
	for _, server := range local.Servers {
		servers = append(servers, server)
	}
	roster := local.GenRosterFromHost(servers...)

	dummyReq := &daga_login.CreateContext{
		SubscribersKeys: protocols_testing.RandomPointSlice(13),
		ServiceID:       daga_login.ServiceID(uuid.Must(uuid.NewV4())),
		DagaNodes:       roster,
		Signature:       make([]byte, 32), // TODO later real signature
	}

	// create and setup root protocol instance + start protocol
	contextGeneration := services[0].(*protocols_testing.DummyService).NewDAGAContextGenerationProtocol(t, dummyReq)

	context, dagaServer, err := contextGeneration.WaitForResult()
	require.NoError(t, err, "failed to get result of protocol run")
	require.NotZero(t, context)

	// verify correctness ...
	members := context.Members()
	contextBytes, err := daga.AuthenticationContextToBytes(context) // TODO see to include other things (roster Ids etc..)
	require.NoError(t, err)
	present := false
	for i, pubKey := range members.Y {
		require.NoError(t, daga.SchnorrVerify(tSuite, pubKey, contextBytes, context.Signatures[i]))
		if pubKey.Equal(dagaServer.PublicKey()) {
			if !present {
				present = true
			} else {
				t.Errorf("same dagaServer present multiple times in context")
			}
		}
	}
}
