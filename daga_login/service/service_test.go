package service

import (
	"errors"
	"github.com/dedis/kyber"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/dedis/student_18_daga/daga_login"
	testing2 "github.com/dedis/student_18_daga/daga_login/testing" // FIXME reorganize now that I use it in service tests too, for now package organization not fixed..
	"github.com/dedis/student_18_daga/sign/daga"
	"github.com/stretchr/testify/require"
	"testing"
)

var tSuite = daga.NewSuiteEC()

func TestMain(m *testing.M) {
	log.MainTest(m)
}

// override/replace the Setup function of the Service(s) with a function that populate their state/storage with
// the dagaServer and context provided
func overrideServicesSetup(services []onet.Service, dagaServers []daga.Server, dummyContext *daga_login.Context) {
	dagaServerFromKey := testing2.DagaServerFromKey(dagaServers)
	for _, s := range services {
		// override setup to plug some test state: (in real life those are (for now) fetched from FS during setupState)
		// TODO create a curry maker outside, I might end up reusing this
		service := s.(*Service)
		service.Setup = func(s *Service) error {
			if s.Storage == nil {
				dagaServer := dagaServerFromKey[s.ServerIdentity().Public.String()]
				context := *dummyContext
				s.Storage = &Storage{
					DagaServer: *daga_login.NetEncodeServer(dagaServer),
					Context:    *context.NetEncode(),
				}
			}
			return nil
		}
	}
}

// verify that PKClient call succeed on valid request
func TestService_PKClient(t *testing.T) {
	local := onet.NewTCPTest(tSuite)  // QUESTION: vs localTest ?
	hosts, roster, _ := local.GenTree(5, true)
	defer local.CloseAll()

	services := local.GetServices(hosts, DagaID)
	_, dagaServers, _, dummyContext := testing2.DummyDagaSetup(local, roster)

	// provide initial state to the service (instead of fetching it from FS)
	overrideServicesSetup(services, dagaServers, dummyContext)

	for _, s := range services {  // QUESTION purpose/point of running test on multiple same service ??
		log.Lvl2("Sending request to", s)

		commitments := testing2.RandomPointSlice(len(dummyContext.ClientsGenerators())*3)

		reply, err := s.(*Service).PKClient(
			&daga_login.PKclientCommitments{
				Context:     *dummyContext.NetEncode(),
				Commitments: commitments},
		)
		require.NoError(t, err)
		require.NotZero(t, reply)

		// verify that all servers correctly signed the challenge
		// QUESTION: not sure if I should test theses here.. IMO the sut is the protocol, not the daga code it uses
		_, Y := dummyContext.Members()
		daga.Challenge(*reply).VerifySignatures(tSuite, Y, commitments)
	}
}

// verify that Auth call succeed on valid request
func TestService_Auth(t *testing.T) {
	local := onet.NewTCPTest(tSuite)  // QUESTION: vs localTest ?
	hosts, roster, _ := local.GenTree(5, true)
	defer local.CloseAll()

	services := local.GetServices(hosts, DagaID)
	_, dagaServers, dummyAuthRequest, dummyContext := testing2.DummyDagaSetup(local, roster)

	// provide initial state to the service (instead of fetching it from FS)
	overrideServicesSetup(services, dagaServers, dummyContext)

	for _, s := range services {  // QUESTION purpose/point of running test on multiple same service ??
		log.Lvl2("Sending request to", s)

		request := daga_login.Auth(*daga_login.NetEncodeAuthenticationMessage(*dummyContext, *dummyAuthRequest))
		reply, err := s.(*Service).Auth(&request)
		require.NoError(t, err)
		require.NotZero(t, reply)

		serverMsg, context, err := daga_login.NetServerMessage(*reply).NetDecode()
		require.NoError(t, err)
		require.True(t, context.Equals(*dummyContext), "context part of reply different than context of request")
		// verify / extract tag
		Tf, err := daga.GetFinalLinkageTag(tSuite, dummyContext, *serverMsg)
		require.NoError(t, err, "failed to extract tag from the resulting serverMsg")
		require.NotZero(t, Tf)
	}
}

func TestValidateAuthReqShouldErrorOnNilReq(t *testing.T) {
	service := &Service{}
	context, err := service.validateAuthReq(nil)
	require.Error(t, err, "should return error on nil req")
	require.Zero(t, context)
}

func TestValidateAuthReqShouldErrorOnEmptyReq(t *testing.T) {
	service := &Service{}
	context, err := service.validateAuthReq((*daga_login.Auth)(&daga_login.NetAuthenticationMessage{
		Context: daga_login.NetContext{},
		T0: nil,
		SCommits: nil,
		Proof: daga.ClientProof{},
	}))
	require.Error(t, err, "should return error on empty req")
	require.Zero(t, context)
}

func TestValidateContextShouldErrorOnInvalidContext(t *testing.T) {
	service := &Service{}
	badNetContext := daga_login.NetContext{
		Roster: onet.Roster{},
		G: struct {
			X []kyber.Point
			Y []kyber.Point
		}{X: testing2.RandomPointSlice(5), Y: testing2.RandomPointSlice(9)},
		H:testing2.RandomPointSlice(3),  // len != 5 => invalid
		R:testing2.RandomPointSlice(8), // len != 9 => invalid
	}
	context, err := service.validateContext(badNetContext)
	require.Error(t, err, "should return error on invalid context")
	require.Zero(t, context)
}

func TestValidateContextShouldErrorOnEmptyRoster(t *testing.T) {
	service := &Service{}
	badNetContext := daga_login.NetContext{
		Roster: onet.Roster{},
		G: struct {
			X []kyber.Point
			Y []kyber.Point
		}{X: testing2.RandomPointSlice(5), Y: testing2.RandomPointSlice(9)},
		H:testing2.RandomPointSlice(5),
		R:testing2.RandomPointSlice(9),
	}
	context, err := service.validateContext(badNetContext)
	require.Error(t, err, "should return error on empty roster")
	require.Zero(t, context)

	badNetContext.Roster = onet.Roster{List: make([]*network.ServerIdentity, 0, 5),
	}
	context, err = service.validateContext(badNetContext)
	require.Error(t, err, "should return error on empty roster")
	require.Zero(t, context)
}

func TestValidateContextShouldErrorOnUnacceptedContext(t *testing.T) {
	local := onet.NewTCPTest(tSuite)
	hosts, roster, _ := local.GenTree(5, true)
	defer local.CloseAll()

	services := local.GetServices(hosts, DagaID)
	_, dagaServers, _, dummyContext := testing2.DummyDagaSetup(local, roster)
	// provide initial state to the service (instead of fetching it from FS)
	overrideServicesSetup(services[0:0], dagaServers, dummyContext)
	service := services[0].(*Service)
	service.Setup(service)

	// same roster but bullshit in daga.Context
	badNetContext := daga_login.NetContext{
		Roster: *roster,
		G: struct {
			X []kyber.Point
			Y []kyber.Point
		}{X: testing2.RandomPointSlice(5), Y: testing2.RandomPointSlice(9)},
		H:testing2.RandomPointSlice(5),
		R:testing2.RandomPointSlice(9),
	}
	context, err := service.validateContext(badNetContext)
	require.Error(t, err, "should return error on not accepted context")
	require.Zero(t, context)
}

func TestValidatePKClientReqShouldErrorOnNilRequest(t *testing.T) {
	service := &Service{}

	context, err := service.validatePKClientReq(nil)
	require.Error(t, err, "should return error on nil request")
	require.Zero(t, context)
}

func TestValidatePKClientReqShouldErrorOnEmptyOrBadlySizedCommitments(t *testing.T) {
	service := &Service{}

	context, err := service.validatePKClientReq(&daga_login.PKclientCommitments{
		Context: daga_login.NetContext{},
	})
	require.Error(t, err, "should return error on empty request")
	require.Zero(t, context)

	context, err = service.validatePKClientReq(&daga_login.PKclientCommitments{
		Context: daga_login.NetContext{
			H: testing2.RandomPointSlice(8),
		},
		Commitments: testing2.RandomPointSlice(12),  // != 3*8
	})
	require.Error(t, err, "should return error on bad commitments size")
	require.Zero(t, context)
}

func TestPKClientShouldErrorOnFailedSetup(t *testing.T) {
	service := &Service{}
	service.Setup = func(s *Service) error {
		return errors.New("not inspired")
	}
	reply, err := service.PKClient(&daga_login.PKclientCommitments{
		Context: daga_login.NetContext{
			H: testing2.RandomPointSlice(8),
		},
		Commitments: testing2.RandomPointSlice(3*8),
	})
	require.Error(t, err, "should return error on failed setup")
	require.Zero(t, reply)
}

func TestAuthShouldErrorOnFailedSetup(t *testing.T) {
	service := &Service{}
	service.Setup = func(s *Service) error {
		return errors.New("not inspired")
	}

	local := onet.NewTCPTest(tSuite)
	_, roster, _ := local.GenTree(5, true)
	defer local.CloseAll()
	_, _, dummyAuthRequest, dummyContext := testing2.DummyDagaSetup(local, roster)

	request := daga_login.Auth(*daga_login.NetEncodeAuthenticationMessage(*dummyContext, *dummyAuthRequest))
	reply, err := service.Auth(&request)
	require.Error(t, err, "should return error on failed setup")
	require.Zero(t, reply)
}