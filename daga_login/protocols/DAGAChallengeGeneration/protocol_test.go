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

const testServiceName = "ServiceOCS"

func init() {
	var err error
	testServiceID, err = onet.RegisterNewService(testServiceName, newDummyService)
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

// returns a new
func newDummyService(c *onet.Context) (onet.Service, error) {
	s := &dummyService{
		ServiceProcessor: onet.NewServiceProcessor(c),
	}
	return s, nil
}

// function called to initialize and start a new DAGAChallengeGeneration protocol where current node takes a Leader role
// "dummy" counterpart of daga_login.service.newDAGAChallengeGenerationProtocol() keep them more or less in sync
func (s dummyService) newDAGAChallengeGenerationProtocol(t *testing.T, reqContext daga_login.Context) (*DAGAChallengeGeneration.DAGAChallengeGenerationProtocol) {
	// build tree with leader as root
	roster := reqContext.Roster
	// pay attention to the fact that for the protocol to work the tree needs to be correctly shaped !!
	// protocol assumes that all other nodes are direct children of leader (use aggregation before calling some handlers)
	tree := roster.GenerateNaryTreeWithRoot(len(roster.List)-1, s.ServerIdentity())

	// create and setup protocol instance (additionally ~test p.NewProtocol)
	pi, err := s.CreateProtocol(DAGAChallengeGeneration.Name, tree)
	require.NoError(t, err, "failed to create " + DAGAChallengeGeneration.Name + " protocol")
	require.NotNil(t, pi, "nil protocol instance but no error")

	challengeGeneration := pi.(*DAGAChallengeGeneration.DAGAChallengeGenerationProtocol)
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
		challengeGeneration := pi.(*DAGAChallengeGeneration.DAGAChallengeGenerationProtocol)

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

func runProtocol(t *testing.T, nbrNodes int) {
	log.Lvl2("Running", DAGAChallengeGeneration.Name , "with", nbrNodes, "nodes")
	local := onet.NewLocalTest(tSuite)
	defer local.CloseAll()

	// local test environment
	servers, roster, tree := local.GenBigTree(nbrNodes, nbrNodes, nbrNodes-1, true)
	services := local.GetServices(servers, testServiceID)
	log.Lvl3("Tree is:", tree.Dump())

	// setup dummy context (real life we grab context from user request)
	var serverKeys []kyber.Scalar
	for _, server := range servers {
		serverKeys = append(serverKeys, local.GetPrivate(server))
	}
	_, dagaServers, minDagaContext, err := daga.GenerateContext(tSuite, rand.Intn(10)+1, serverKeys)
	require.NoError(t, err)
	dummyContext, err := daga_login.NewContext(minDagaContext, *roster)
	require.NoError(t, err)

	// populate dummy service states (real life we will need a setup protocol/procedure)
	for i, service := range services {
		service := service.(*dummyService)
		service.dagaServer = dagaServers[i]
		// TODO/FIXME maybe avoid making assumptions on the sort order of the various slices...build a dict
	}

	// create and setup root protocol instance + start protocol
	challengeGeneration := services[0].(*dummyService).newDAGAChallengeGenerationProtocol(t, *dummyContext)

	challenge, err := challengeGeneration.WaitForResult()
	require.NoError(t, err, "failed to get result of protocol run")
	require.NotZero(t, challenge)
	// TODO now what to test on resulting challenge + here ? (vs in sign/daga etc..)
}

// TODO test protocol methods and functions in isolation
