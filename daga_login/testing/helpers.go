package testing

import (
	"errors"
	"github.com/dedis/kyber"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/student_18_daga/daga_login"
	"github.com/dedis/student_18_daga/daga_login/protocols/DAGA"
	"github.com/dedis/student_18_daga/daga_login/protocols/DAGAChallengeGeneration"
	"github.com/dedis/student_18_daga/daga_login/protocols/DAGAContextGeneration"
	"github.com/dedis/student_18_daga/sign/daga"
	"github.com/satori/go.uuid"
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

// dummyService to provide state to the protocol instances/play role of parent service when testing the *protocols*
type DummyService struct {
	// We need to embed the ServiceProcessor, so that incoming messages
	// are correctly handled.
	*onet.ServiceProcessor

	// Has to be initialised by the tests
	DagaServer    daga.Server
	AcceptContext func(daga_login.Context) (daga.Server, error)
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
func (s DummyService) NewDAGAChallengeGenerationProtocol(t *testing.T, req daga_login.PKclientCommitments) *DAGAChallengeGeneration.Protocol {
	// build tree with leader as root
	roster := req.Context.Roster
	// pay attention to the fact that for the protocol to work the tree needs to be correctly shaped !!
	// protocol assumes that all other nodes are direct children of leader (use aggregation before calling some handlers)
	tree := roster.GenerateNaryTreeWithRoot(len(roster.List)-1, s.ServerIdentity())

	// create and setup protocol instance (additionally ~test p.NewProtocol)
	pi, err := s.CreateProtocol(DAGAChallengeGeneration.Name, tree)
	require.NoError(t, err, "failed to create "+DAGAChallengeGeneration.Name+" protocol")
	require.NotNil(t, pi, "nil protocol instance but no error")

	challengeGeneration := pi.(*DAGAChallengeGeneration.Protocol)
	challengeGeneration.LeaderSetup(req, s.DagaServer)

	// start
	err = challengeGeneration.Start()
	require.NoError(t, err, "failed to start %s protocol: %s", DAGAChallengeGeneration.Name, err)

	log.Lvlf3("service started %s protocol, waiting for completion", DAGAChallengeGeneration.Name)
	return challengeGeneration
}

// function called to initialize and start a new DAGA server protocol where current node takes a Leader role
// "dummy" counterpart of daga_login.service.newDAGAServerProtocol() keep them more or less in sync
func (s DummyService) NewDAGAServerProtocol(t *testing.T, req daga_login.Auth) *DAGA.Protocol {
	// build tree with leader as root
	roster := req.Context.Roster
	// pay attention to the fact that for the protocol to work the tree needs to be correctly shaped !!
	// protocol assumes that all other nodes are direct children of leader (use aggregation before calling some handlers)
	tree := roster.GenerateNaryTreeWithRoot(len(roster.List)-1, s.ServerIdentity())

	// create and setup protocol instance (additionally ~test p.NewProtocol)
	pi, err := s.CreateProtocol(DAGA.Name, tree)
	require.NoError(t, err, "failed to create "+DAGA.Name+" protocol")
	require.NotNil(t, pi, "nil protocol instance but no error")

	dagaProtocol := pi.(*DAGA.Protocol)
	dagaProtocol.LeaderSetup(req, s.DagaServer)

	// start
	err = dagaProtocol.Start()
	require.NoError(t, err, "failed to start %s protocol: %s", DAGA.Name, err)

	log.Lvlf3("service started %s protocol, waiting for completion", DAGA.Name)
	return dagaProtocol
}

// function called to initialize and start a new DAGA server protocol where current node takes a Leader role
// "dummy" counterpart of daga_login.service.newDAGAServerProtocol() keep them more or less in sync
func (s DummyService) NewDAGAContextGenerationProtocol(t *testing.T, req *daga_login.CreateContext) *DAGAContextGeneration.Protocol {
	// build tree with leader as root
	roster := req.DagaNodes
	// pay attention to the fact that, for the protocol to work, the tree needs to be correctly shaped !!
	// protocol assumes that all other nodes are direct children of leader (use aggregation before calling some handlers)
	tree := roster.GenerateNaryTreeWithRoot(len(roster.List)-1, s.ServerIdentity())

	// create and setup protocol instance
	pi, err := s.CreateProtocol(DAGAContextGeneration.Name, tree)
	require.NoError(t, err, "failed to create "+DAGAContextGeneration.Name)
	require.NotNil(t, pi, "nil protocol instance but no error")
	contextGeneration := pi.(*DAGAContextGeneration.Protocol)
	contextGeneration.LeaderSetup(req)

	// start
	err = contextGeneration.Start()
	require.NoError(t, err, "failed to start %s protocol: %s", DAGA.Name, err)

	log.Lvlf3("service started %s protocol, waiting for completion", DAGAContextGeneration.Name)
	return contextGeneration
}

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
		challengeGeneration.ChildSetup(func(req *daga_login.PKclientCommitments) (daga.Server, error) {
			return s.AcceptContext(req.Context)
		})
		return challengeGeneration, nil
	case DAGA.Name:
		pi, err := DAGA.NewProtocol(tn)
		if err != nil {
			return nil, err
		}
		dagaProtocol := pi.(*DAGA.Protocol)
		dagaProtocol.ChildSetup(s.AcceptContext)
		return dagaProtocol, nil
	case DAGAContextGeneration.Name:
		pi, err := DAGAContextGeneration.NewProtocol(tn)
		if err != nil {
			return nil, err
		}
		contextGeneration := pi.(*DAGAContextGeneration.Protocol)
		contextGeneration.ChildSetup(func(req *daga_login.CreateContext) error {
			return nil // we don't have much to check.., we're testing the protocols, and the function is used only to test complete valid run in principle
		}, func(context daga_login.Context, dagaServer daga.Server) error {
			return nil // same don't need to do anything with the results
		})
		return contextGeneration, nil
	default:
		log.Panic("protocol not implemented/known")
	}
	return nil, errors.New("should not be reached")
}

// TODO add possibility to return bad challenge channel
func DummyDagaSetup(local *onet.LocalTest, roster *onet.Roster) (dagaClients []daga.Client, dagaServers []daga.Server,
	dummyAuthRequest *daga.AuthenticationMessage, dummyContext *daga_login.Context) {

	dagaClients, dagaServers, minDagaContext, err := daga.GenerateTestContext(tSuite, rand.Intn(10)+2, len(local.Servers))
	if err != nil {
		log.Panic(err.Error())
	}
	dummyContext, _ = daga_login.NewContext(minDagaContext, roster, daga_login.ServiceID(uuid.Must(uuid.NewV4())), nil)

	// TODO QUESTION what would be the best way to share test helpers with sign/daga (have the ~same) new daga testing package with all helper ?
	dummyChallengeChannel := func(commitments []kyber.Point) (daga.Challenge, error) {
		// TODO share helper with kyber daga tests ?? (~same helper used)
		challenge := daga.Challenge{
			Cs: tSuite.Scalar().Pick(tSuite.RandomStream()),
		}
		signData, err := challenge.ToBytes(commitments)
		if err != nil {
			return daga.Challenge{}, err
		}
		var sigs []daga.ServerSignature
		//Make each test server sign the challenge
		for _, server := range dagaServers {
			if sig, err := daga.SchnorrSign(tSuite, server.PrivateKey(), signData); err != nil {
				return daga.Challenge{}, err
			} else {
				sigs = append(sigs, daga.ServerSignature{Index: server.Index(), Sig: sig})
			}
		}
		challenge.Sigs = sigs
		return challenge, nil
	}

	dummyAuthRequest, _ = daga.NewAuthenticationMessage(tSuite, dummyContext, dagaClients[0], dummyChallengeChannel)
	return
}

func DagaServerFromKey(dagaServers []daga.Server) map[string]daga.Server {
	dagaServerFromKey := make(map[string]daga.Server)
	for _, dagaServer := range dagaServers {
		dagaServerFromKey[dagaServer.PublicKey().String()] = dagaServer
	}
	return dagaServerFromKey
}

// used to test the protocols, dummy test service
func ValidServiceSetup(local *onet.LocalTest, nbrNodes int) ([]onet.Service, *daga.AuthenticationMessage, *daga_login.Context) {
	// local test environment
	servers, roster, tree := local.GenBigTree(nbrNodes, nbrNodes, nbrNodes-1, true)
	services := local.GetServices(servers, TestServiceID)
	log.Lvl3("Tree is:", tree.Dump())

	// setup dummy request
	_, dagaServers, dummyRequest, dummyContext := DummyDagaSetup(local, roster)

	// populate dummy service states (real life we will need a setup protocol/procedure)
	for i, service := range services {
		service := service.(*DummyService)
		service.DagaServer = dagaServers[i]
		service.AcceptContext = func(context daga_login.Context) (daga.Server, error) {
			if context.Equals(*dummyContext) {
				return service.DagaServer, nil
			} else {
				return nil, errors.New("not accepted")
			}
		}
	}

	return services, dummyRequest, dummyContext
}

func RandomPointSlice(len int) []kyber.Point {
	points := make([]kyber.Point, 0, len)
	for i := 0; i < len; i++ {
		points = append(points, tSuite.Point().Pick(tSuite.RandomStream()))
	}
	return points
}
