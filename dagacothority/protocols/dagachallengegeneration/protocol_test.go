package dagachallengegeneration_test

import (
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/student_18_daga/dagacothority"
	"github.com/dedis/student_18_daga/dagacothority/protocols/dagachallengegeneration"
	protocols_testing "github.com/dedis/student_18_daga/dagacothority/testing"
	"github.com/dedis/student_18_daga/sign/daga"
	"github.com/stretchr/testify/require"
	"math/rand"
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
	log.Lvl2("Running", dagachallengegeneration.Name, "with", nbrNodes, "nodes")
	local := onet.NewLocalTest(tSuite)
	defer local.CloseAll()

	services, _, dummyContext := protocols_testing.ValidServiceSetup(local, nbrNodes)
	dummyReq := dagacothority.PKclientCommitments{
		Context:     *dummyContext,
		Commitments: protocols_testing.RandomPointSlice(len(dummyContext.ClientsGenerators()) * 3),
	}

	// create and setup root protocol instance + start protocol
	serviceIndex := rand.Intn(len(services))
	challengeGeneration := services[serviceIndex].(*protocols_testing.DummyService).NewDAGAChallengeGenerationProtocol(t, dummyReq)

	challenge, err := challengeGeneration.WaitForResult()
	require.NoError(t, err, "failed to get result of protocol run")
	require.NotZero(t, challenge)

	// verify that all servers correctly signed the challenge
	// QUESTION: not sure if I should test theses here.. IMO the sut is the protocol, not the daga code it uses
	members := dummyContext.Members()
	challenge.VerifySignatures(tSuite, members.Y, dummyReq.Commitments)
}

func TestLeaderSetup(t *testing.T) {
	local := onet.NewLocalTest(tSuite)
	defer local.CloseAll()

	// valid setup, should not panic
	nbrNodes := 1
	_, roster, tree := local.GenBigTree(nbrNodes, nbrNodes, nbrNodes-1, true)
	_, dagaServers, _, dummyContext := protocols_testing.DummyDagaSetup(rand.Intn(10)+2, len(local.Servers), roster)
	dummyReq := dagacothority.PKclientCommitments{
		Context:     *dummyContext,
		Commitments: protocols_testing.RandomPointSlice(len(dummyContext.ClientsGenerators()) * 3),
	}
	pi, _ := local.CreateProtocol(dagachallengegeneration.Name, tree)
	defer pi.(*dagachallengegeneration.Protocol).Done()

	require.NotPanics(t, func() {
		pi.(*dagachallengegeneration.Protocol).LeaderSetup(dummyReq, dagaServers[0])
	}, "should not panic on valid input")
}

func TestLeaderSetupShouldPanicOnEmptyContext(t *testing.T) {
	local := onet.NewLocalTest(tSuite)
	defer local.CloseAll()

	nbrNodes := 1
	_, roster, tree := local.GenBigTree(nbrNodes, nbrNodes, nbrNodes-1, true)
	_, dagaServers, _, _ := protocols_testing.DummyDagaSetup(rand.Intn(10)+2, len(local.Servers), roster)
	pi, _ := local.CreateProtocol(dagachallengegeneration.Name, tree)
	defer pi.(*dagachallengegeneration.Protocol).Done()

	require.Panics(t, func() {
		pi.(*dagachallengegeneration.Protocol).LeaderSetup(dagacothority.PKclientCommitments{}, dagaServers[0])
	}, "should panic on empty req")
}

func TestLeaderSetupShouldPanicOnBadCommitmentsLength(t *testing.T) {
	local := onet.NewLocalTest(tSuite)
	defer local.CloseAll()

	nbrNodes := 1
	_, roster, tree := local.GenBigTree(nbrNodes, nbrNodes, nbrNodes-1, true)
	_, dagaServers, _, dummyContext := protocols_testing.DummyDagaSetup(rand.Intn(10)+2, len(local.Servers), roster)
	pi, _ := local.CreateProtocol(dagachallengegeneration.Name, tree)
	defer pi.(*dagachallengegeneration.Protocol).Done()

	require.Panics(t, func() {
		pi.(*dagachallengegeneration.Protocol).LeaderSetup(dagacothority.PKclientCommitments{
			Commitments: protocols_testing.RandomPointSlice(len(dummyContext.ClientsGenerators())),
			Context:     *dummyContext,
		}, dagaServers[0])
	}, "should panic on bad commitments size")
}

func TestLeaderSetupShouldPanicOnNilServer(t *testing.T) {
	local := onet.NewLocalTest(tSuite)
	defer local.CloseAll()

	nbrNodes := 1
	_, roster, tree := local.GenBigTree(nbrNodes, nbrNodes, nbrNodes-1, true)
	_, _, _, dummyContext := protocols_testing.DummyDagaSetup(rand.Intn(10)+2, len(local.Servers), roster)
	dummyReq := dagacothority.PKclientCommitments{
		Context:     *dummyContext,
		Commitments: protocols_testing.RandomPointSlice(len(dummyContext.ClientsGenerators()) * 3),
	}
	pi, _ := local.CreateProtocol(dagachallengegeneration.Name, tree)
	defer pi.(*dagachallengegeneration.Protocol).Done()

	require.Panics(t, func() {
		pi.(*dagachallengegeneration.Protocol).LeaderSetup(dummyReq, nil)
	}, "should panic on nil server")
}

func TestLeaderSetupShouldPanicOnInvalidState(t *testing.T) {
	local := onet.NewLocalTest(tSuite)
	defer local.CloseAll()

	nbrNodes := 1
	_, roster, tree := local.GenBigTree(nbrNodes, nbrNodes, nbrNodes-1, true)
	_, dagaServers, _, dummyContext := protocols_testing.DummyDagaSetup(rand.Intn(10)+2, len(local.Servers), roster)
	dummyReq := dagacothority.PKclientCommitments{
		Context:     *dummyContext,
		Commitments: protocols_testing.RandomPointSlice(len(dummyContext.ClientsGenerators()) * 3),
	}
	pi, _ := local.CreateProtocol(dagachallengegeneration.Name, tree)

	pi.(*dagachallengegeneration.Protocol).LeaderSetup(dummyReq, dagaServers[0])
	require.Panics(t, func() {
		pi.(*dagachallengegeneration.Protocol).LeaderSetup(dummyReq, dagaServers[0])
	}, "should panic on already initialized node")
	pi.(*dagachallengegeneration.Protocol).Done()

	pi, _ = local.CreateProtocol(dagachallengegeneration.Name, tree)
	defer pi.(*dagachallengegeneration.Protocol).Done()

	pi.(*dagachallengegeneration.Protocol).ChildSetup(func(*dagacothority.PKclientCommitments) (daga.Server, error) {
		return dagaServers[0], nil
	})
	require.Panics(t, func() {
		pi.(*dagachallengegeneration.Protocol).LeaderSetup(dummyReq, dagaServers[0])
	}, "should panic on already initialized node")
}

func TestChildrenSetup(t *testing.T) {
	local := onet.NewLocalTest(tSuite)
	defer local.CloseAll()

	// valid setup, should not panic
	nbrNodes := 1
	_, roster, tree := local.GenBigTree(nbrNodes, nbrNodes, nbrNodes-1, true)
	_, dagaServers, _, _ := protocols_testing.DummyDagaSetup(rand.Intn(10)+2, len(local.Servers), roster)
	pi, _ := local.CreateProtocol(dagachallengegeneration.Name, tree)
	defer pi.(*dagachallengegeneration.Protocol).Done()

	require.NotPanics(t, func() {
		pi.(*dagachallengegeneration.Protocol).ChildSetup(func(*dagacothority.PKclientCommitments) (daga.Server, error) {
			return dagaServers[0], nil
		})
	}, "should not panic on valid input")
}

func TestChildrenSetupShouldPanicOnNilServer(t *testing.T) {
	local := onet.NewLocalTest(tSuite)
	defer local.CloseAll()

	nbrNodes := 1
	_, _, tree := local.GenBigTree(nbrNodes, nbrNodes, nbrNodes-1, true)
	pi, _ := local.CreateProtocol(dagachallengegeneration.Name, tree)
	defer pi.(*dagachallengegeneration.Protocol).Done()

	require.Panics(t, func() {
		pi.(*dagachallengegeneration.Protocol).ChildSetup(nil)
	}, "should panic on nil server")
}

func TestChildrenSetupShouldPanicOnInvalidState(t *testing.T) {
	local := onet.NewLocalTest(tSuite)
	defer local.CloseAll()

	nbrNodes := 1
	_, roster, tree := local.GenBigTree(nbrNodes, nbrNodes, nbrNodes-1, true)
	_, dagaServers, _, dummyContext := protocols_testing.DummyDagaSetup(rand.Intn(10)+2, len(local.Servers), roster)
	dummyReq := dagacothority.PKclientCommitments{
		Context:     *dummyContext,
		Commitments: protocols_testing.RandomPointSlice(len(dummyContext.ClientsGenerators()) * 3),
	}
	pi, _ := local.CreateProtocol(dagachallengegeneration.Name, tree)

	pi.(*dagachallengegeneration.Protocol).ChildSetup(func(*dagacothority.PKclientCommitments) (daga.Server, error) {
		return dagaServers[0], nil
	})
	require.Panics(t, func() {
		pi.(*dagachallengegeneration.Protocol).ChildSetup(func(*dagacothority.PKclientCommitments) (daga.Server, error) {
			return dagaServers[0], nil
		})
	}, "should panic on already initialized node")
	pi.(*dagachallengegeneration.Protocol).Done()

	pi, _ = local.CreateProtocol(dagachallengegeneration.Name, tree)
	defer pi.(*dagachallengegeneration.Protocol).Done()

	pi.(*dagachallengegeneration.Protocol).LeaderSetup(dummyReq, dagaServers[0])
	require.Panics(t, func() {
		pi.(*dagachallengegeneration.Protocol).ChildSetup(func(*dagacothority.PKclientCommitments) (daga.Server, error) {
			return dagaServers[0], nil
		})
	}, "should panic on already initialized node")
}

func TestStartShouldErrorOnInvalidTreeShape(t *testing.T) {
	local := onet.NewLocalTest(tSuite)
	defer local.CloseAll()

	nbrNodes := 5
	_, roster, tree := local.GenBigTree(nbrNodes, nbrNodes, 2, true)
	_, dagaServers, _, dummyContext := protocols_testing.DummyDagaSetup(rand.Intn(10)+2, len(local.Servers), roster)
	dummyReq := dagacothority.PKclientCommitments{
		Context:     *dummyContext,
		Commitments: protocols_testing.RandomPointSlice(len(dummyContext.ClientsGenerators()) * 3),
	}
	pi, _ := local.CreateProtocol(dagachallengegeneration.Name, tree)
	pi.(*dagachallengegeneration.Protocol).LeaderSetup(dummyReq, dagaServers[0])
	require.Error(t, pi.Start(), "should return error, tree has invalid shape (protocol expects that all other nodes are direct children of root)")
}

//
//func TestWaitForResultShouldErrorOnTimeout(t *testing.T) {
//	local := onet.NewLocalTest(tSuite)
//	defer local.CloseAll()
//
//
//}

func TestWaitForResultShouldPanicIfCalledBeforeStart(t *testing.T) {
	local := onet.NewLocalTest(tSuite)
	defer local.CloseAll()

	nbrNodes := 5
	_, roster, tree := local.GenBigTree(nbrNodes, nbrNodes, 2, true)
	_, dagaServers, _, dummyContext := protocols_testing.DummyDagaSetup(rand.Intn(10)+2, len(local.Servers), roster)
	dummyReq := dagacothority.PKclientCommitments{
		Context:     *dummyContext,
		Commitments: protocols_testing.RandomPointSlice(len(dummyContext.ClientsGenerators()) * 3),
	}
	pi, _ := local.CreateProtocol(dagachallengegeneration.Name, tree)
	defer pi.(*dagachallengegeneration.Protocol).Done()

	pi.(*dagachallengegeneration.Protocol).LeaderSetup(dummyReq, dagaServers[0])
	require.Panics(t, func() {
		pi.(*dagachallengegeneration.Protocol).WaitForResult()
	})
}

func TestWaitForResultShouldPanicOnNonRootInstance(t *testing.T) {
	local := onet.NewLocalTest(tSuite)
	defer local.CloseAll()

	nbrNodes := 5
	_, roster, tree := local.GenBigTree(nbrNodes, nbrNodes, 2, true)
	_, dagaServers, _, _ := protocols_testing.DummyDagaSetup(rand.Intn(10)+2, len(local.Servers), roster)
	pi, _ := local.CreateProtocol(dagachallengegeneration.Name, tree)
	defer pi.(*dagachallengegeneration.Protocol).Done()

	// TODO test name little misleading but ..

	pi.(*dagachallengegeneration.Protocol).ChildSetup(func(*dagacothority.PKclientCommitments) (daga.Server, error) {
		return dagaServers[0], nil
	})
	require.Panics(t, func() {
		pi.(*dagachallengegeneration.Protocol).WaitForResult()
	})
}

// QUESTION TODO don't know how to test more advanced things, how to simulate bad behavior from some nodes
// now I'm only assured that it works when setup like intended + some little bad things
// but no guarantees on what happens otherwise

// TODO test handlers (for Done too)
