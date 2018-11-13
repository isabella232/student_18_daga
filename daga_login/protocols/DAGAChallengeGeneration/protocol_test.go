package DAGAChallengeGeneration_test

import (
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/student_18_daga/daga_login"
	"github.com/dedis/student_18_daga/daga_login/protocols/DAGAChallengeGeneration"
	protocols_testing "github.com/dedis/student_18_daga/daga_login/testing"
	"github.com/dedis/student_18_daga/sign/daga"
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
	log.Lvl2("Running", DAGAChallengeGeneration.Name, "with", nbrNodes, "nodes")
	local := onet.NewLocalTest(tSuite)
	defer local.CloseAll()

	services, _, dummyContext := protocols_testing.ValidServiceSetup(local, nbrNodes)
	dummyReq := daga_login.PKclientCommitments{
		Context:     *dummyContext,
		Commitments: protocols_testing.RandomPointSlice(len(dummyContext.ClientsGenerators()) * 3),
	}

	// create and setup root protocol instance + start protocol
	challengeGeneration := services[0].(*protocols_testing.DummyService).NewDAGAChallengeGenerationProtocol(t, dummyReq)

	challenge, err := challengeGeneration.WaitForResult()
	require.NoError(t, err, "failed to get result of protocol run")
	require.NotZero(t, challenge)

	// verify that all servers correctly signed the challenge
	// QUESTION: not sure if I should test theses here.. IMO the sut is the protocol, not the daga code it uses
	_, Y := dummyContext.Members()
	challenge.VerifySignatures(tSuite, Y, dummyReq.Commitments)
}

func TestLeaderSetup(t *testing.T) {
	local := onet.NewLocalTest(tSuite)
	defer local.CloseAll()

	// valid setup, should not panic
	nbrNodes := 1
	_, roster, tree := local.GenBigTree(nbrNodes, nbrNodes, nbrNodes-1, true)
	_, dagaServers, _, dummyContext := protocols_testing.DummyDagaSetup(local, roster)
	dummyReq := daga_login.PKclientCommitments{
		Context:     *dummyContext,
		Commitments: protocols_testing.RandomPointSlice(len(dummyContext.ClientsGenerators()) * 3),
	}
	pi, _ := local.CreateProtocol(DAGAChallengeGeneration.Name, tree)
	defer pi.(*DAGAChallengeGeneration.Protocol).Done()

	require.NotPanics(t, func() {
		pi.(*DAGAChallengeGeneration.Protocol).LeaderSetup(dummyReq, dagaServers[0])
	}, "should not panic on valid input")
}

func TestLeaderSetupShouldPanicOnEmptyContext(t *testing.T) {
	local := onet.NewLocalTest(tSuite)
	defer local.CloseAll()

	nbrNodes := 1
	_, roster, tree := local.GenBigTree(nbrNodes, nbrNodes, nbrNodes-1, true)
	_, dagaServers, _, _ := protocols_testing.DummyDagaSetup(local, roster)
	pi, _ := local.CreateProtocol(DAGAChallengeGeneration.Name, tree)
	defer pi.(*DAGAChallengeGeneration.Protocol).Done()

	require.Panics(t, func() {
		pi.(*DAGAChallengeGeneration.Protocol).LeaderSetup(daga_login.PKclientCommitments{}, dagaServers[0])
	}, "should panic on empty req")
}

func TestLeaderSetupShouldPanicOnBadCommitmentsLength(t *testing.T) {
	local := onet.NewLocalTest(tSuite)
	defer local.CloseAll()

	nbrNodes := 1
	_, roster, tree := local.GenBigTree(nbrNodes, nbrNodes, nbrNodes-1, true)
	_, dagaServers, _, dummyContext := protocols_testing.DummyDagaSetup(local, roster)
	pi, _ := local.CreateProtocol(DAGAChallengeGeneration.Name, tree)
	defer pi.(*DAGAChallengeGeneration.Protocol).Done()

	require.Panics(t, func() {
		pi.(*DAGAChallengeGeneration.Protocol).LeaderSetup(daga_login.PKclientCommitments{
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
	_, _, _, dummyContext := protocols_testing.DummyDagaSetup(local, roster)
	dummyReq := daga_login.PKclientCommitments{
		Context:     *dummyContext,
		Commitments: protocols_testing.RandomPointSlice(len(dummyContext.ClientsGenerators()) * 3),
	}
	pi, _ := local.CreateProtocol(DAGAChallengeGeneration.Name, tree)
	defer pi.(*DAGAChallengeGeneration.Protocol).Done()

	require.Panics(t, func() {
		pi.(*DAGAChallengeGeneration.Protocol).LeaderSetup(dummyReq, nil)
	}, "should panic on nil server")
}

func TestLeaderSetupShouldPanicOnInvalidState(t *testing.T) {
	local := onet.NewLocalTest(tSuite)
	defer local.CloseAll()

	nbrNodes := 1
	_, roster, tree := local.GenBigTree(nbrNodes, nbrNodes, nbrNodes-1, true)
	_, dagaServers, _, dummyContext := protocols_testing.DummyDagaSetup(local, roster)
	dummyReq := daga_login.PKclientCommitments{
		Context:     *dummyContext,
		Commitments: protocols_testing.RandomPointSlice(len(dummyContext.ClientsGenerators()) * 3),
	}
	pi, _ := local.CreateProtocol(DAGAChallengeGeneration.Name, tree)

	pi.(*DAGAChallengeGeneration.Protocol).LeaderSetup(dummyReq, dagaServers[0])
	require.Panics(t, func() {
		pi.(*DAGAChallengeGeneration.Protocol).LeaderSetup(dummyReq, dagaServers[0])
	}, "should panic on already initialized node")
	pi.(*DAGAChallengeGeneration.Protocol).Done()

	pi, _ = local.CreateProtocol(DAGAChallengeGeneration.Name, tree)
	defer pi.(*DAGAChallengeGeneration.Protocol).Done()

	pi.(*DAGAChallengeGeneration.Protocol).ChildSetup(func(daga_login.Context) (daga.Server, error) {
		return dagaServers[0], nil
	})
	require.Panics(t, func() {
		pi.(*DAGAChallengeGeneration.Protocol).LeaderSetup(dummyReq, dagaServers[0])
	}, "should panic on already initialized node")
}

func TestChildrenSetup(t *testing.T) {
	local := onet.NewLocalTest(tSuite)
	defer local.CloseAll()

	// valid setup, should not panic
	nbrNodes := 1
	_, roster, tree := local.GenBigTree(nbrNodes, nbrNodes, nbrNodes-1, true)
	_, dagaServers, _, _ := protocols_testing.DummyDagaSetup(local, roster)
	pi, _ := local.CreateProtocol(DAGAChallengeGeneration.Name, tree)
	defer pi.(*DAGAChallengeGeneration.Protocol).Done()

	require.NotPanics(t, func() {
		pi.(*DAGAChallengeGeneration.Protocol).ChildSetup(func(daga_login.Context) (daga.Server, error) {
			return dagaServers[0], nil
		})
	}, "should not panic on valid input")
}

func TestChildrenSetupShouldPanicOnNilServer(t *testing.T) {
	local := onet.NewLocalTest(tSuite)
	defer local.CloseAll()

	nbrNodes := 1
	_, _, tree := local.GenBigTree(nbrNodes, nbrNodes, nbrNodes-1, true)
	pi, _ := local.CreateProtocol(DAGAChallengeGeneration.Name, tree)
	defer pi.(*DAGAChallengeGeneration.Protocol).Done()

	require.Panics(t, func() {
		pi.(*DAGAChallengeGeneration.Protocol).ChildSetup(nil)
	}, "should panic on nil server")
}

func TestChildrenSetupShouldPanicOnInvalidState(t *testing.T) {
	local := onet.NewLocalTest(tSuite)
	defer local.CloseAll()

	nbrNodes := 1
	_, roster, tree := local.GenBigTree(nbrNodes, nbrNodes, nbrNodes-1, true)
	_, dagaServers, _, dummyContext := protocols_testing.DummyDagaSetup(local, roster)
	dummyReq := daga_login.PKclientCommitments{
		Context:     *dummyContext,
		Commitments: protocols_testing.RandomPointSlice(len(dummyContext.ClientsGenerators()) * 3),
	}
	pi, _ := local.CreateProtocol(DAGAChallengeGeneration.Name, tree)

	pi.(*DAGAChallengeGeneration.Protocol).ChildSetup(func(daga_login.Context) (daga.Server, error) {
		return dagaServers[0], nil
	})
	require.Panics(t, func() {
		pi.(*DAGAChallengeGeneration.Protocol).ChildSetup(func(daga_login.Context) (daga.Server, error) {
			return dagaServers[0], nil
		})
	}, "should panic on already initialized node")
	pi.(*DAGAChallengeGeneration.Protocol).Done()

	pi, _ = local.CreateProtocol(DAGAChallengeGeneration.Name, tree)
	defer pi.(*DAGAChallengeGeneration.Protocol).Done()

	pi.(*DAGAChallengeGeneration.Protocol).LeaderSetup(dummyReq, dagaServers[0])
	require.Panics(t, func() {
		pi.(*DAGAChallengeGeneration.Protocol).ChildSetup(func(daga_login.Context) (daga.Server, error) {
			return dagaServers[0], nil
		})
	}, "should panic on already initialized node")
}

func TestStartShouldErrorOnInvalidTreeShape(t *testing.T) {
	local := onet.NewLocalTest(tSuite)
	defer local.CloseAll()

	nbrNodes := 5
	_, roster, tree := local.GenBigTree(nbrNodes, nbrNodes, 2, true)
	_, dagaServers, _, dummyContext := protocols_testing.DummyDagaSetup(local, roster)
	dummyReq := daga_login.PKclientCommitments{
		Context:     *dummyContext,
		Commitments: protocols_testing.RandomPointSlice(len(dummyContext.ClientsGenerators()) * 3),
	}
	pi, _ := local.CreateProtocol(DAGAChallengeGeneration.Name, tree)
	pi.(*DAGAChallengeGeneration.Protocol).LeaderSetup(dummyReq, dagaServers[0])
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
	_, dagaServers, _, dummyContext := protocols_testing.DummyDagaSetup(local, roster)
	dummyReq := daga_login.PKclientCommitments{
		Context:     *dummyContext,
		Commitments: protocols_testing.RandomPointSlice(len(dummyContext.ClientsGenerators()) * 3),
	}
	pi, _ := local.CreateProtocol(DAGAChallengeGeneration.Name, tree)
	defer pi.(*DAGAChallengeGeneration.Protocol).Done()

	pi.(*DAGAChallengeGeneration.Protocol).LeaderSetup(dummyReq, dagaServers[0])
	require.Panics(t, func() {
		pi.(*DAGAChallengeGeneration.Protocol).WaitForResult()
	})
}

func TestWaitForResultShouldPanicOnNonRootInstance(t *testing.T) {
	local := onet.NewLocalTest(tSuite)
	defer local.CloseAll()

	nbrNodes := 5
	_, roster, tree := local.GenBigTree(nbrNodes, nbrNodes, 2, true)
	_, dagaServers, _, _ := protocols_testing.DummyDagaSetup(local, roster)
	pi, _ := local.CreateProtocol(DAGAChallengeGeneration.Name, tree)
	defer pi.(*DAGAChallengeGeneration.Protocol).Done()

	// TODO test name little misleading but ..

	pi.(*DAGAChallengeGeneration.Protocol).ChildSetup(func(daga_login.Context) (daga.Server, error) {
		return dagaServers[0], nil
	})
	require.Panics(t, func() {
		pi.(*DAGAChallengeGeneration.Protocol).WaitForResult()
	})
}

// QUESTION TODO don't know how to test more advanced things, how to simulate bad behavior from some nodes
// now I'm only assured that it works when setup like intended + some little bad things
// but no guarantees on what happens otherwise

// TODO test handlers (for Done too)
