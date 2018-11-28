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

//// QUESTION pKClient is not exported (doesn't make sense) => to test it need to be in same package => import cycle...
//// or test it indirectly through Auth calls..
//func TestClient_pKCLient(t *testing.T) {
//	nbr := 5
//	local := onet.NewTCPTest(tSuite)
//	// generate 5 hosts, they don't connect, they process messages, and they
//	// don't register the tree or entitylist
//	_, roster, _ := local.GenTree(nbr, false)
//	defer local.CloseAll()
//
//	_, _, dummyContext := testing2.DummyDagaSetup(local, roster)
//
//	c, _ := NewClient(0, nil)
//	challenge := c.pKClient(roster.RandomServerIdentity(), *dummyContext, testing2.RandomPointSlice(3*len(dummyContext.ClientsGenerators())))
//
//	// verify that all servers correctly signed the challenge
//	bytes, _ := challenge.Cs.MarshalBinary()
//	_, Y := dummyContext.Members()
//	for _, signature := range challenge.Sigs {
//		require.NoError(t, daga.SchnorrVerify(tSuite, Y[signature.Index], bytes, signature.Sig))
//	}
//}

// override/replace the Setup function of the Service(s) with a function that populate their state/storage with
// the dagaServer and context provided
// TODO helper used to test service too => better to move to testing helpers => but KO import cycles..
func overrideServicesSetup(services []onet.Service, dagaServers []daga.Server, dummyContext *dagacothority.Context) {
	for i, s := range services {
		// override setup to plug some test state: (in real life those are (for now) fetched from FS during setupState)
		svc := s.(*service.Service)
		svc.Setup = func(index int) func(s *service.Service) error {
			return func(s *service.Service) error {
				if s.Storage == nil {
					dagaServer := dagaServers[index]
					s.Storage = &service.Storage{
						State: service.State(map[dagacothority.ServiceID]*service.ServiceState{
							dummyContext.ServiceID: {
								ID: dummyContext.ServiceID,
								ContextStates: map[dagacothority.ContextID]*service.ContextState{
									dummyContext.ContextID: {
										DagaServer: *dagacothority.NetEncodeServer(dagaServer),
										Context:    *dummyContext,
									},
								},
							},
						}),
					}
				}
				return nil
			}
		}(i)
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

	overrideServicesSetup(services, dagaServers, dummyContext)
	return local, dagaClients[0], dummyContext
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
