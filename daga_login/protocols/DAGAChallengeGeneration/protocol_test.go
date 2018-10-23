package protocol_test

/*
The test-file should at the very least run the protocol for a varying number
of nodes. It is even better practice to test the different methods of the
protocol, as in Test Driven Development.
*/

import (
	"github.com/dedis/student_18_daga/sign/daga"
	"testing"
	"time"

	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/dedis/student_18_daga/daga_login/protocol"
	"github.com/stretchr/testify/require"
)

var tSuite = daga.NewSuiteEC()

func TestMain(m *testing.M) {
	log.MainTest(m)
}

// Tests a 2, 5 and 13-node system. It is good practice to test different
// sizes of trees to make sure your protocol is stable.
func TestNode(t *testing.T) {
	nodes := []int{2, 5, 13}
	for _, nbrNodes := range nodes {
		local := onet.NewLocalTest(tSuite)
		_, _, tree := local.GenTree(nbrNodes, true)
		log.Lvl3(tree.Dump())

		pi, err := local.StartProtocol(protocol.Name, tree)
		require.NoError(t, err)
		protocol := pi.(*protocol.DAGAChallengeGenerationProtocol)
		timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*nbrNodes*2) * time.Millisecond
		select {
		case children := <-protocol.ChildCount:
			log.Lvl2("Instance 1 is done")
			require.Equal(t, children, nbrNodes, "Didn't get a child-cound of", nbrNodes)
		case <-time.After(timeout):
			t.Fatal("Didn't finish in time")
		}
		local.CloseAll()
	}
}
