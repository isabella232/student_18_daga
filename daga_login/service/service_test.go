package service

import (
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/student_18_daga/daga_login"
	testing2 "github.com/dedis/student_18_daga/daga_login/protocols/testing"
	// FIXME reorganize now that I use it in service tests too, for now package organization not fixed..
	"github.com/dedis/student_18_daga/sign/daga"
	"github.com/stretchr/testify/require"
	"testing"
)

var tSuite = daga.NewSuiteEC()

func TestMain(m *testing.M) {
	log.MainTest(m, 5)
}

func TestService_PKClient(t *testing.T) {
	local := onet.NewTCPTest(tSuite)  // QUESTION: vs localTest ?
	hosts, roster, _ := local.GenTree(5, true)
	defer local.CloseAll()

	services := local.GetServices(hosts, dagaID)
	dagaServers, dummyAuthRequest, dummyContext := testing2.DummyDagaSetup(local, roster)
	dagaServerFromKey := testing2.DagaServerFromKey(dagaServers)
	for _, s := range services {
		// setup: (in real life those are (for now) fetched from FS during tryLoad)
		// plug some state setting function
		// TODO create a curry maker outside, I might end up reusing this
		service := s.(*Service)
		service.Setup = func(s *Service) error {
			if s.storage == nil {
				dagaServer := dagaServerFromKey[s.ServerIdentity().Public.String()]
				context := *dummyContext
				s.storage = &storage{
					DagaServer: *daga_login.NetEncodeServer(dagaServer),
					Context:    *context.NetEncode(),
				}
			}
			return nil
		}
	}

	for _, s := range services {  // QUESTION purpose of running test on multiple same service ??

		log.Lvl2("Sending request to", s)

		reply, err := s.(*Service).PKClient(
			&daga_login.PKclientCommitments{
				Context: *dummyContext.NetEncode(),
				Data: dummyAuthRequest.P0.T},  // here can use new fresh random ones instead
		)
		require.NoError(t, err)
		require.NotZero(t, reply)
	}
}
