package DAGAChallengeGeneration_test
//
///*
//The test-file should at the very least run the protocols for a varying number
//of nodes. It is even better practice to test the different methods of the
//protocols, as in Test Driven Development.
//*/
//
//import (
//	"github.com/dedis/student_18_daga/daga_login/protocols/DAGAChallengeGeneration"
//	"github.com/dedis/student_18_daga/sign/daga"
//	"testing"
//	"time"
//
//	"github.com/dedis/onet"
//	"github.com/dedis/onet/log"
//	"github.com/dedis/onet/network"
//	"github.com/stretchr/testify/require"
//)
//
//var tSuite = daga.NewSuiteEC()
//
//func TestMain(m *testing.M) {
//	log.MainTest(m)
//}
//
//// Tests a 2, 5 and 13-node system.
//func TestChallengeGeneration(t *testing.T) {
//	nodes := []int{2, 5, 13}
//	for _, nbrNodes := range nodes {
//		testNode(t, nbrNodes)
//	}
//}
//
//func testNode(t *testing.T, nbrNodes int) {
//	local := onet.NewLocalTest(tSuite)
//	defer local.CloseAll()
//	_, _, tree := local.GenTree(nbrNodes, true)
//	log.Lvl3(tree.Dump())
//
//	// QUESTION how to give state to services (my protocol is not testable as is without services..need state)
//	// here I can give state to leader, fine but how to control
//
//	local.StartProtocol()
//	pi, err := local.CreateProtocol(DAGAChallengeGeneration.Name, tree)
//	require.NoError(t, err)
//	protocol := pi.(*DAGAChallengeGeneration.DAGAChallengeGenerationProtocol)
//	timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*nbrNodes*2) * time.Millisecond
//	select {
//	case children := <-protocol.ChildCount:
//		log.Lvl2("Instance 1 is done")
//		require.Equal(t, children, nbrNodes, "Didn't get a child-cound of", nbrNodes)
//	case <-time.After(timeout):
//		t.Fatal("Didn't finish in time")
//	}
//}
