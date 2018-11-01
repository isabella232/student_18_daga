package DAGAChallengeGeneration_test

/*
The test-file should at the very least run the protocols for a varying number
of nodes. It is even better practice to test the different methods of the
protocols, as in Test Driven Development.
*/

import (
	"errors"
	"github.com/dedis/kyber"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/student_18_daga/daga_login"
	"github.com/dedis/student_18_daga/daga_login/protocols/DAGAChallengeGeneration"
	"github.com/dedis/student_18_daga/sign/daga"
	"github.com/stretchr/testify/require"
	"math/rand"
	"testing"
)

var tSuite = daga.NewSuiteEC()

// Used for tests
var testServiceID onet.ServiceID

const testService = "testService"

func init() {
	var err error
	testServiceID, err = onet.RegisterNewService(testService, newDummyService)
	log.ErrFatal(err)
}

func TestMain(m *testing.M) {
	log.MainTest(m)
}

// dummyService to provide state to the protocol instances
type dummyService struct {
	// We need to embed the ServiceProcessor, so that incoming messages
	// are correctly handled.
	*onet.ServiceProcessor

	// Has to be initialised by the test
	dagaServer daga.Server
}

// returns a new dummyService
func newDummyService(c *onet.Context) (onet.Service, error) {
	s := &dummyService{
		ServiceProcessor: onet.NewServiceProcessor(c),
	}
	return s, nil
}

// function called to initialize and start a new DAGAChallengeGeneration protocol where current node takes a Leader role
// "dummy" counterpart of daga_login.service.newDAGAChallengeGenerationProtocol() keep them more or less in sync
func (s dummyService) newDAGAChallengeGenerationProtocol(t *testing.T, reqContext daga_login.Context) (*DAGAChallengeGeneration.Protocol) {
	// build tree with leader as root
	roster := reqContext.Roster
	// pay attention to the fact that for the protocol to work the tree needs to be correctly shaped !!
	// protocol assumes that all other nodes are direct children of leader (use aggregation before calling some handlers)
	tree := roster.GenerateNaryTreeWithRoot(len(roster.List)-1, s.ServerIdentity())

	// create and setup protocol instance (additionally ~test p.NewProtocol)
	pi, err := s.CreateProtocol(DAGAChallengeGeneration.Name, tree)
	require.NoError(t, err, "failed to create " + DAGAChallengeGeneration.Name + " protocol")
	require.NotNil(t, pi, "nil protocol instance but no error")

	challengeGeneration := pi.(*DAGAChallengeGeneration.Protocol)
	challengeGeneration.LeaderSetup(reqContext, s.dagaServer)

	// start
	err = challengeGeneration.Start()
	require.NoError(t, err, "failed to start %s protocol: %s", DAGAChallengeGeneration.Name, err)

	log.Lvlf3("service started %s protocol, waiting for completion", DAGAChallengeGeneration.Name)
	return challengeGeneration
}

// NewProtocol is called upon reception of a Protocol's first message when Onet needs
// to instantiate the protocol. A Service is expected to manually create
// the ProtocolInstance it is using. So this method will be potentially called on all nodes of a Tree (except the root, since it is
// the one starting the protocols) to generate the PI on those other nodes.
// "dummy" counterpart of daga_login.service.NewProtocol() keep them more or less in sync
func (s *dummyService) NewProtocol(tn *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl3("received protocol msg, instantiating new protocol instance of " + tn.ProtocolName())
	switch tn.ProtocolName() {
	case DAGAChallengeGeneration.Name:
		pi, err := DAGAChallengeGeneration.NewProtocol(tn)
		if err != nil {
			return nil, err
		}
		challengeGeneration := pi.(*DAGAChallengeGeneration.Protocol)

		challengeGeneration.ChildrenSetup(s.dagaServer)
		return challengeGeneration, nil
	default:
		log.Panic("protocol not implemented/known")
	}
	return nil, errors.New("should not be reached")
}

// Tests a 2, 5 and 13-node system. (complete protocol run)
func TestChallengeGeneration(t *testing.T) {
	nodes := []int{2, 5, 13}
	for _, nbrNodes := range nodes {
		runProtocol(t, nbrNodes)
	}
}

// TODO more DRY helpers fair share of code is .. shared..

func dummyDagaSetup(local *onet.LocalTest, roster *onet.Roster) (dagaServers []daga.Server, dummyContext *daga_login.Context){
	var serverKeys []kyber.Scalar
	servers := local.Servers
	for _, server := range servers {
		serverKeys = append(serverKeys, local.GetPrivate(server))
	}
	_, dagaServers, minDagaContext, _ := daga.GenerateContext(tSuite, rand.Intn(10)+1, serverKeys)
	dummyContext, _ = daga_login.NewContext(minDagaContext, *roster)
	return
}

func validServiceSetup(local *onet.LocalTest, nbrNodes int) ([]onet.Service, *daga_login.Context) {

	// local test environment
	servers, roster, tree := local.GenBigTree(nbrNodes, nbrNodes, nbrNodes-1, true)
	services := local.GetServices(servers, testServiceID)
	log.Lvl3("Tree is:", tree.Dump())

	// setup dummy context (real life we grab context from user request)
	dagaServers, dummyContext := dummyDagaSetup(local, roster)

	// populate dummy service states (real life we will need a setup protocol/procedure)
	dagaServerFromKey := make(map[string]daga.Server)
	for _, dagaServer := range dagaServers {
		dagaServerFromKey[dagaServer.PublicKey().String()] = dagaServer
	}
	for _, service := range services {
		service := service.(*dummyService)
		service.dagaServer = dagaServerFromKey[service.ServerIdentity().Public.String()]
	}

	return services, dummyContext

}


func runProtocol(t *testing.T, nbrNodes int) {
	log.Lvl2("Running", DAGAChallengeGeneration.Name , "with", nbrNodes, "nodes")
	local := onet.NewLocalTest(tSuite)
	defer local.CloseAll()

	services, dummyContext := validServiceSetup(local, nbrNodes)

	// create and setup root protocol instance + start protocol
	challengeGeneration := services[0].(*dummyService).newDAGAChallengeGenerationProtocol(t, *dummyContext)

	challenge, err := challengeGeneration.WaitForResult()
	require.NoError(t, err, "failed to get result of protocol run")
	require.NotZero(t, challenge)

	// verify that all servers correctly signed the challenge
	// QUESTION: not sure if I should test theses here.. IMO the sut is the protocol, not the daga code it uses
	// QUESTION: and I have a daga function that is currently private that do that..
	bytes, _ := challenge.Cs.MarshalBinary()
	_, Y := dummyContext.Members()
	for _, signature := range challenge.Sigs {
		require.NoError(t, daga.SchnorrVerify(tSuite, Y[signature.Index], bytes, signature.Sig))
	}
}

func TestLeaderSetup(t *testing.T) {
	local := onet.NewLocalTest(tSuite)
	defer local.CloseAll()

	// valid setup, should not panic
	nbrNodes := 1
	_, roster, tree := local.GenBigTree(nbrNodes, nbrNodes, nbrNodes-1, true)
	dagaServers, dummyContext := dummyDagaSetup(local, roster)
	pi, _ := local.CreateProtocol(DAGAChallengeGeneration.Name, tree)
	defer pi.(*DAGAChallengeGeneration.Protocol).Done()

	require.NotPanics(t, func() {
		pi.(*DAGAChallengeGeneration.Protocol).LeaderSetup(*dummyContext, dagaServers[0])
	}, "should not panic on valid input")
}

func TestLeaderSetupShouldPanicOnEmptyContext(t *testing.T) {
	local := onet.NewLocalTest(tSuite)
	defer local.CloseAll()

	nbrNodes := 1
	_, roster, tree := local.GenBigTree(nbrNodes, nbrNodes, nbrNodes-1, true)
	dagaServers, _ := dummyDagaSetup(local, roster)
	pi, _ := local.CreateProtocol(DAGAChallengeGeneration.Name, tree)
	defer pi.(*DAGAChallengeGeneration.Protocol).Done()

	require.Panics(t, func() {
		pi.(*DAGAChallengeGeneration.Protocol).LeaderSetup(daga_login.Context{}, dagaServers[0])
	}, "should panic on empty context")
}

func TestLeaderSetupShouldPanicOnNilServer(t *testing.T) {
	local := onet.NewLocalTest(tSuite)
	defer local.CloseAll()

	nbrNodes := 1
	_, roster, tree := local.GenBigTree(nbrNodes, nbrNodes, nbrNodes-1, true)
	_, dummyContext := dummyDagaSetup(local, roster)
	pi, _ := local.CreateProtocol(DAGAChallengeGeneration.Name, tree)
	defer pi.(*DAGAChallengeGeneration.Protocol).Done()

	require.Panics(t, func() {
		pi.(*DAGAChallengeGeneration.Protocol).LeaderSetup(*dummyContext, nil)
	}, "should panic on nil server")
}

func TestLeaderSetupShouldPanicOnInvalidState(t *testing.T) {
	local := onet.NewLocalTest(tSuite)
	defer local.CloseAll()

	nbrNodes := 1
	_, roster, tree := local.GenBigTree(nbrNodes, nbrNodes, nbrNodes-1, true)
	dagaServers, dummyContext := dummyDagaSetup(local, roster)
	pi, _ := local.CreateProtocol(DAGAChallengeGeneration.Name, tree)

	pi.(*DAGAChallengeGeneration.Protocol).LeaderSetup(*dummyContext, dagaServers[0])
	require.Panics(t, func() {
		pi.(*DAGAChallengeGeneration.Protocol).LeaderSetup(*dummyContext, dagaServers[0])
	}, "should panic on already initialized server")
	pi.(*DAGAChallengeGeneration.Protocol).Done()


	pi, _ = local.CreateProtocol(DAGAChallengeGeneration.Name, tree)
	defer pi.(*DAGAChallengeGeneration.Protocol).Done()

	pi.(*DAGAChallengeGeneration.Protocol).ChildrenSetup(dagaServers[0])
	require.Panics(t, func() {
		pi.(*DAGAChallengeGeneration.Protocol).LeaderSetup(*dummyContext, dagaServers[0])
	}, "should panic on already initialized server")
}

func TestChildrenSetup(t *testing.T) {
	local := onet.NewLocalTest(tSuite)
	defer local.CloseAll()

	// valid setup, should not panic
	nbrNodes := 1
	_, roster, tree := local.GenBigTree(nbrNodes, nbrNodes, nbrNodes-1, true)
	dagaServers, _ := dummyDagaSetup(local, roster)
	pi, _ := local.CreateProtocol(DAGAChallengeGeneration.Name, tree)
	defer pi.(*DAGAChallengeGeneration.Protocol).Done()

	require.NotPanics(t, func() {
		pi.(*DAGAChallengeGeneration.Protocol).ChildrenSetup(dagaServers[0])
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
		pi.(*DAGAChallengeGeneration.Protocol).ChildrenSetup(nil)
	}, "should panic on nil server")
}

func TestChildrenSetupShouldPanicOnInvalidState(t *testing.T) {
	local := onet.NewLocalTest(tSuite)
	defer local.CloseAll()

	nbrNodes := 1
	_, roster, tree := local.GenBigTree(nbrNodes, nbrNodes, nbrNodes-1, true)
	dagaServers, dummyContext := dummyDagaSetup(local, roster)
	pi, _ := local.CreateProtocol(DAGAChallengeGeneration.Name, tree)

	pi.(*DAGAChallengeGeneration.Protocol).ChildrenSetup(dagaServers[0])
	require.Panics(t, func() {
		pi.(*DAGAChallengeGeneration.Protocol).ChildrenSetup(dagaServers[0])
	}, "should panic on already initialized server")
	pi.(*DAGAChallengeGeneration.Protocol).Done()


	pi, _ = local.CreateProtocol(DAGAChallengeGeneration.Name, tree)
	defer pi.(*DAGAChallengeGeneration.Protocol).Done()

	pi.(*DAGAChallengeGeneration.Protocol).LeaderSetup(*dummyContext, dagaServers[0])
	require.Panics(t, func() {
		pi.(*DAGAChallengeGeneration.Protocol).ChildrenSetup(dagaServers[0])
	}, "should panic on already initialized server")
}

func TestStartShouldErrorOnInvalidTreeShape(t *testing.T) {
	local := onet.NewLocalTest(tSuite)
	defer local.CloseAll()

	nbrNodes := 5
	_, roster, tree := local.GenBigTree(nbrNodes, nbrNodes, 2, true)
	dagaServers, dummyContext := dummyDagaSetup(local, roster)
	pi, _ := local.CreateProtocol(DAGAChallengeGeneration.Name, tree)
	defer pi.(*DAGAChallengeGeneration.Protocol).Done()
	pi.(*DAGAChallengeGeneration.Protocol).LeaderSetup(*dummyContext, dagaServers[0])
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
	dagaServers, dummyContext := dummyDagaSetup(local, roster)
	pi, _ := local.CreateProtocol(DAGAChallengeGeneration.Name, tree)
	defer pi.(*DAGAChallengeGeneration.Protocol).Done()

	pi.(*DAGAChallengeGeneration.Protocol).LeaderSetup(*dummyContext, dagaServers[0])
	require.Panics(t, func() {
		pi.(*DAGAChallengeGeneration.Protocol).WaitForResult()
	})
}

func TestWaitForResultShouldPanicOnNonRootInstance(t *testing.T) {
	local := onet.NewLocalTest(tSuite)
	defer local.CloseAll()

	nbrNodes := 5
	_, roster, tree := local.GenBigTree(nbrNodes, nbrNodes, 2, true)
	dagaServers, _ := dummyDagaSetup(local, roster)
	pi, _ := local.CreateProtocol(DAGAChallengeGeneration.Name, tree)
	defer pi.(*DAGAChallengeGeneration.Protocol).Done()

	// TODO test name little misleading but ..

	pi.(*DAGAChallengeGeneration.Protocol).ChildrenSetup(dagaServers[0])
	require.Panics(t, func() {
		pi.(*DAGAChallengeGeneration.Protocol).WaitForResult()
	})
}

// QUESTION TODO don't know how to test more advanced things, how to simulate bad behavior from some nodes
// now I'm only assured that it works when setup like intended + some little bad things
// but no guarantees on what happens otherwise