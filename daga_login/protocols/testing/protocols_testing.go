package testing

import (
	"errors"
	"github.com/dedis/kyber"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/student_18_daga/daga_login"
	"github.com/dedis/student_18_daga/daga_login/protocols/DAGA"
	"github.com/dedis/student_18_daga/daga_login/protocols/DAGAChallengeGeneration"
	"github.com/dedis/student_18_daga/sign/daga"
	"github.com/stretchr/testify/require"
	"math/rand"
	"testing"
)

var tSuite = daga.NewSuiteEC()

// Used for tests
var TestServiceID onet.ServiceID

const TestServiceName = "dummyDagaService"

func init() {
	var err error
	TestServiceID, err = onet.RegisterNewService(TestServiceName, NewDummyService)
	log.ErrFatal(err)
}

// dummyService to provide state to the protocol instances
type DummyService struct {
	// We need to embed the ServiceProcessor, so that incoming messages
	// are correctly handled.
	*onet.ServiceProcessor

	// Has to be initialised by the tests
	DagaServer daga.Server
	AcceptContext func(daga_login.Context)bool
}

// returns a new dummyService
func NewDummyService(c *onet.Context) (onet.Service, error) {
	s := &DummyService{
		ServiceProcessor: onet.NewServiceProcessor(c),
	}
	return s, nil
}

// function called to initialize and start a new DAGAChallengeGeneration protocol where current node takes a Leader role
// "dummy" counterpart of daga_login.service.newDAGAChallengeGenerationProtocol() keep them more or less in sync
func (s DummyService) NewDAGAChallengeGenerationProtocol(t *testing.T, reqContext daga_login.Context) (*DAGAChallengeGeneration.Protocol) {
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
	challengeGeneration.LeaderSetup(reqContext, s.DagaServer)

	// start
	err = challengeGeneration.Start()
	require.NoError(t, err, "failed to start %s protocol: %s", DAGAChallengeGeneration.Name, err)

	log.Lvlf3("service started %s protocol, waiting for completion", DAGAChallengeGeneration.Name)
	return challengeGeneration
}

// function called to initialize and start a new DAGA server protocol where current node takes a Leader role
// "dummy" counterpart of daga_login.service.newDAGAServerProtocol() keep them more or less in sync
func (s DummyService) NewDAGAServerProtocol(t *testing.T, req daga_login.NetAuthenticationMessage) (*DAGA.Protocol) {
	// build tree with leader as root
	roster := req.Context.Roster
	// pay attention to the fact that for the protocol to work the tree needs to be correctly shaped !!
	// protocol assumes that all other nodes are direct children of leader (use aggregation before calling some handlers)
	tree := roster.GenerateNaryTreeWithRoot(len(roster.List)-1, s.ServerIdentity())

	// create and setup protocol instance (additionally ~test p.NewProtocol)
	pi, err := s.CreateProtocol(DAGA.Name, tree)
	require.NoError(t, err, "failed to create " + DAGA.Name + " protocol")
	require.NotNil(t, pi, "nil protocol instance but no error")

	dagaProtocol := pi.(*DAGA.Protocol)
	dagaProtocol.LeaderSetup(req, s.DagaServer)

	// start
	err = dagaProtocol.Start()
	require.NoError(t, err, "failed to start %s protocol: %s", DAGA.Name, err)

	log.Lvlf3("service started %s protocol, waiting for completion", DAGA.Name)
	return dagaProtocol
}

// NewProtocol is called upon reception of a Protocol's first message when Onet needs
// to instantiate the protocol. A Service is expected to manually create
// the ProtocolInstance it is using. So this method will be potentially called on all nodes of a Tree (except the root, since it is
// the one starting the protocols) to generate the PI on those other nodes.
// "dummy" counterpart of daga_login.service.NewProtocol() keep them more or less in sync
func (s *DummyService) NewProtocol(tn *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl3("received protocol msg, instantiating new protocol instance of " + tn.ProtocolName())
	switch tn.ProtocolName() {
	case DAGAChallengeGeneration.Name:
		pi, err := DAGAChallengeGeneration.NewProtocol(tn)
		if err != nil {
			return nil, err
		}
		challengeGeneration := pi.(*DAGAChallengeGeneration.Protocol)

		challengeGeneration.ChildrenSetup(s.DagaServer)
		return challengeGeneration, nil
	case DAGA.Name:
		pi, err := DAGA.NewProtocol(tn)
		if err != nil {
			return nil, err
		}
		dagaProtocol := pi.(*DAGA.Protocol)

		dagaProtocol.ChildrenSetup(s.DagaServer, s.AcceptContext)
		return dagaProtocol, nil
	default:
		log.Panic("protocol not implemented/known")
	}
	return nil, errors.New("should not be reached")
}

// TODO add possibility to return bad challenge channel
func DummyDagaSetup(local *onet.LocalTest, roster *onet.Roster) (dagaServers []daga.Server,
	dummyAuthRequest *daga.AuthenticationMessage, dummyContext *daga_login.Context){
	var serverKeys []kyber.Scalar
	servers := local.Servers
	for _, server := range servers {
		serverKeys = append(serverKeys, local.GetPrivate(server))
	}
	dagaClients, dagaServers, minDagaContext, _ := daga.GenerateContext(tSuite, rand.Intn(10)+2, serverKeys)
	dummyContext, _ = daga_login.NewContext(minDagaContext, *roster)

	// TODO QUESTION what would be the best way to share test helpers with sign/daga (have the ~same) new daga testing package with all helper ?
	dummyChallengeChannel := func(commitments []kyber.Point) daga.Challenge {
		cs := tSuite.Scalar().Pick(tSuite.RandomStream())
		msg, _ := cs.MarshalBinary()
		var sigs []daga.ServerSignature
		//Make each test server sign the challenge
		for _, server := range dagaServers {
			sig, _ := daga.SchnorrSign(tSuite, server.PrivateKey(), msg)
			sigs = append(sigs, daga.ServerSignature{Index: server.Index(), Sig: sig})
		}
		return daga.Challenge{Cs: cs, Sigs: sigs}
	}

	dummyAuthRequest, _ = daga.NewAuthenticationMessage(tSuite, dummyContext, dagaClients[0], dummyChallengeChannel)
	return
}

func ValidServiceSetup(local *onet.LocalTest, nbrNodes int) ([]onet.Service, *daga.AuthenticationMessage, *daga_login.Context) {
	// local test environment
	servers, roster, tree := local.GenBigTree(nbrNodes, nbrNodes, nbrNodes-1, true)
	services := local.GetServices(servers, TestServiceID)
	log.Lvl3("Tree is:", tree.Dump())

	// setup dummy request
	dagaServers, dummyRequest, dummyContext := DummyDagaSetup(local, roster)

	// populate dummy service states (real life we will need a setup protocol/procedure)
	dagaServerFromKey := make(map[string]daga.Server)
	for _, dagaServer := range dagaServers {
		dagaServerFromKey[dagaServer.PublicKey().String()] = dagaServer
	}
	for _, service := range services {
		service := service.(*DummyService)
		service.DagaServer = dagaServerFromKey[service.ServerIdentity().Public.String()]
		service.AcceptContext = func(context daga_login.Context) bool {
			return context.Equals(*dummyContext)
		}
	}

	return services, dummyRequest, dummyContext
}