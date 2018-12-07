package dagacothority_test

import (
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/student_18_daga/dagacothority"
	"github.com/dedis/student_18_daga/dagacothority/service"
	testing2 "github.com/dedis/student_18_daga/dagacothority/testing"
	"github.com/dedis/student_18_daga/sign/daga"
	"github.com/stretchr/testify/require"
	"testing"
)

var tSuite = daga.NewSuiteEC()

func TestMain(m *testing.M) {
	log.MainTest(m)
}

// populate services state/storage with the dagaServers and context provided
// TODO helper used to test service too => better to move to testing helpers => but KO import cycles.. => find better solution/organization than copy pasta
func populateServicesStates(services []onet.Service, dagaServers []daga.Server, dummyContext *dagacothority.Context) {
	for i, s := range services {
		// plug some initial test state: (in real life those are (for now) fetched from FS during setupState)
		svc := s.(*service.Service)
		dagaServer := dagaServers[i]
		svc.PopulateServiceState(dummyContext, dagaServer)
	}
}

func authSetup() (*onet.LocalTest, daga.Client, *dagacothority.Context) {
	nbr := 5
	local := onet.NewTCPTest(tSuite)
	// generate 5 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	hosts, roster, _ := local.GenTree(nbr, false)
	services := local.GetServices(hosts, service.DagaID)

	dagaClients, dagaServers, _, dummyContext := testing2.DummyDagaSetup(local, roster)

	populateServicesStates(services, dagaServers, dummyContext)
	return local, dagaClients[0], dummyContext
}

// (pKCLient not exported => test it indirectly through NewPKclientVerifier )
func TestClient_pKCLient(t *testing.T) {
	local, _, dummyContext := authSetup()
	defer local.CloseAll()

	c, _ := dagacothority.NewClient(0, nil)
	pkClientVerifier := c.NewPKclientVerifier(*dummyContext, dummyContext.Roster.RandomServerIdentity())

	commitments := testing2.RandomPointSlice(3 * len(dummyContext.ClientsGenerators()))
	challenge, err := pkClientVerifier(commitments)
	require.NoError(t, err)
	require.NotZero(t, challenge)

	// verify that all servers correctly signed the challenge
	members := dummyContext.Members()
	require.NoError(t, challenge.VerifySignatures(suite, members.Y, commitments))
}

func TestClient_InvalidAuth(t *testing.T) {
	local, _, dummyContext := authSetup()
	defer local.CloseAll()

	// client not part of context
	c, _ := dagacothority.NewClient(0, nil)
	Tf, err := c.Auth(*dummyContext)
	require.Error(t, err, "should error, client not part of context")
	require.Zero(t, Tf)
}

func TestClient_Auth(t *testing.T) {
	local, dagaClient, dummyContext := authSetup()
	defer local.CloseAll()

	// client part of context
	c := dagacothority.Client{
		Client: dagaClient,
		Onet:   onet.NewClient(tSuite, dagacothority.ServiceName),
	}

	Tf, err := c.Auth(*dummyContext)
	require.NoError(t, err, "should not error, client part of context")
	require.NotZero(t, Tf)
}

func TestAdminCLient_CreateContext(t *testing.T) {
	nbr := 5
	local := onet.NewTCPTest(tSuite)
	_, roster, _ := local.GenTree(nbr, false)
	defer local.CloseAll()

	serviceProviderAdmin := dagacothority.NewAdminClient()
	subscriberKeys := testing2.RandomPointSlice(32)
	context, err := serviceProviderAdmin.CreateContext(subscriberKeys, roster)

	// checks
	require.NoError(t, err)
	require.NotZero(t, context)
	require.True(t, dagacothority.ContainsSameElems(subscriberKeys, context.Members().X))
	contextBytes, err := daga.AuthenticationContextToBytes(context)
	require.NoError(t, err)
	for i, pubKey := range context.Members().Y {
		require.NoError(t, daga.SchnorrVerify(tSuite, pubKey, contextBytes, context.Signatures[i]))
	}
}

func BenchmarkClient_Auth(b *testing.B) {
	local, dagaClient, dummyContext := authSetup()
	defer local.CloseAll()

	// client part of context
	c := dagacothority.Client{
		Client: dagaClient,
		Onet:   onet.NewClient(tSuite, dagacothority.ServiceName),
	}

	for i := 0; i < b.N; i++ {
		c.Auth(*dummyContext)
	}
}
