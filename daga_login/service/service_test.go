package service

import (
	"errors"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/util/key"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/dedis/student_18_daga/daga_login"
	testing2 "github.com/dedis/student_18_daga/daga_login/testing"
	"github.com/dedis/student_18_daga/sign/daga"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"testing"
)

// TODO refactor test helpers, create helpers that build various requests, and have the test that test API endpoints accept request as parameter

var tSuite = daga.NewSuiteEC()

func TestMain(m *testing.M) {
	log.MainTest(m, 4)
}

// override/replace the Setup function of the Service(s) with a function that populate their state/storage with
// the dagaServers and context provided
func overrideServicesSetup(services []onet.Service, dagaServers []daga.Server, context daga_login.Context) {
	for i, s := range services {
		// override setup to plug some test state: (in real life those are (for now) fetched from FS during setupState)
		service := s.(*Service)
		service.Setup = func(index int) func(s *Service) error {
			return func(s *Service) error {
				if s.Storage == nil {
					dagaServer := dagaServers[index]
					s.Storage = &Storage{
						State: State(map[daga_login.ServiceID]*ServiceState{
							context.ServiceID: {
								ID: context.ServiceID,
								ContextStates: map[daga_login.ContextID]*ContextState{
									context.ContextID: {
										DagaServer: *daga_login.NetEncodeServer(dagaServer),
										Context:    context,
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

// verify that CreateContext call succeed on valid request
func TestService_CreateContext(t *testing.T) {
	local := onet.NewTCPTest(tSuite)
	hosts, roster, _ := local.GenTree(5, true)
	defer local.CloseAll()

	services := local.GetServices(hosts, DagaID)

	// override Setup
	unusedServers := make([]daga.Server, 0, len(services))
	for _, _ = range services {
		dagaServer, _ := daga.NewServer(tSuite, 0, nil)
		unusedServers = append(unusedServers, dagaServer)
	}
	unusedContext := daga_login.Context{}
	overrideServicesSetup(services, unusedServers, unusedContext)

	for _, s := range services {
		log.Lvl2("Sending request to", s)

		// create valid request
		request := daga_login.CreateContext{
			ServiceID:       daga_login.ServiceID(uuid.Must(uuid.NewV4())),
			DagaNodes:       roster,
			SubscribersKeys: testing2.RandomPointSlice(32),
		}

		// TODO use openPGP (now there is no verification at all)
		keyPair := key.NewKeyPair(tSuite)
		hasher := tSuite.Hash()
		hasher.Write(uuid.UUID(request.ServiceID).Bytes())
		pointBytes, err := daga.PointArrayToBytes(request.SubscribersKeys)
		require.NoError(t, err)
		hasher.Write(pointBytes)
		// TODO auth roster too..
		signature, err := daga.SchnorrSign(tSuite, keyPair.Private, hasher.Sum(nil))
		request.Signature = signature

		reply, err := s.(*Service).CreateContext(&request)
		require.NoError(t, err)
		require.NotZero(t, reply)
		require.NotZero(t, reply.Context)

		// verify correctness ...
		context := reply.Context
		members := context.Members()
		contextBytes, err := daga.AuthenticationContextToBytes(context) // TODO see to include other things (roster Ids etc..)
		require.NoError(t, err)
		for i, pubKey := range members.Y {
			require.NoError(t, daga.SchnorrVerify(tSuite, pubKey, contextBytes, context.Signatures[i]))
		}
	}
}

// verify that PKClient call succeed on valid request
func TestService_PKClient(t *testing.T) {
	local := onet.NewTCPTest(tSuite) // QUESTION: vs localTest ?
	hosts, roster, _ := local.GenTree(5, true)
	defer local.CloseAll()

	services := local.GetServices(hosts, DagaID)
	_, dagaServers, _, dummyContext := testing2.DummyDagaSetup(local, roster)

	// provide initial state to the service (instead of fetching it from FS)
	overrideServicesSetup(services, dagaServers, *dummyContext)

	for _, s := range services { // QUESTION purpose/point of running test on multiple same service ??
		log.Lvl2("Sending request to", s)

		commitments := testing2.RandomPointSlice(len(dummyContext.ClientsGenerators()) * 3)

		reply, err := s.(*Service).PKClient(
			&daga_login.PKclientCommitments{
				Context:     *dummyContext,
				Commitments: commitments},
		)
		require.NoError(t, err)
		require.NotZero(t, reply)

		// verify that all servers correctly signed the challenge
		// QUESTION: not sure if I should test theses here.. IMO the sut is the service, not the daga code or protocol it uses
		members := dummyContext.Members()
		reply.NetDecode().VerifySignatures(tSuite, members.Y, commitments)
	}
}

// verify that Auth call succeed on valid request
func TestService_Auth(t *testing.T) {
	local := onet.NewTCPTest(tSuite) // QUESTION: vs localTest ?
	hosts, roster, _ := local.GenTree(5, true)
	defer local.CloseAll()

	services := local.GetServices(hosts, DagaID)
	_, dagaServers, dummyAuthRequest, dummyContext := testing2.DummyDagaSetup(local, roster)

	// provide initial state to the service (instead of fetching it from FS)
	overrideServicesSetup(services, dagaServers, *dummyContext)

	for _, s := range services { // QUESTION purpose/point of running test on multiple same service ??
		log.Lvl2("Sending request to", s)

		request := daga_login.Auth(*daga_login.NetEncodeAuthenticationMessage(*dummyContext, *dummyAuthRequest))
		reply, err := s.(*Service).Auth(&request)
		require.NoError(t, err)
		require.NotZero(t, reply)

		serverMsg, context := reply.NetDecode()
		require.True(t, context.Equals(*dummyContext), "context part of reply different than context of request")
		// verify / extract tag
		Tf, err := daga.GetFinalLinkageTag(tSuite, dummyContext, *serverMsg)
		require.NoError(t, err, "failed to extract tag from the resulting serverMsg")
		require.NotZero(t, Tf)
	}
}

// verify that PKClient works for context created with CreateContext
// TODO test other pairs of interactions
func TestService_CreateContextAndPKClient(t *testing.T) {
	local := onet.NewTCPTest(tSuite)
	hosts, roster, _ := local.GenTree(5, true)
	defer local.CloseAll()

	services := local.GetServices(hosts, DagaID)

	for _, s := range services {

		// calls CreateContext
		context, _ := getTestContext(t, s.(*Service), roster, 5)

		commitments := testing2.RandomPointSlice(len(context.ClientsGenerators()) * 3)
		reply, err := s.(*Service).PKClient(
			&daga_login.PKclientCommitments{
				Context:     context,
				Commitments: commitments},
		)
		require.NoError(t, err)
		require.NotZero(t, reply)

		// verify that all servers correctly signed the challenge
		// QUESTION: not sure if I should test theses here.. IMO the sut is the service, not the daga code or protocol it uses
		members := context.Members()
		require.NoError(t, reply.NetDecode().VerifySignatures(tSuite, members.Y, commitments))
		//time.Sleep(2*time.Second)
	}
}

// retrieve a test context created by calling the CreateContext endpoint with dummy parameters, to use it in other tests
func getTestContext(t *testing.T, s *Service, roster *onet.Roster, numClients int) (daga_login.Context, []daga.Client) {

	clients := make([]daga.Client, numClients)
	keys := make([]kyber.Point, 0, numClients)
	for i, _ := range clients {
		client, err := daga.NewClient(tSuite, i, nil)
		require.NoError(t, err)
		clients[i] = client
		keys = append(keys, client.PublicKey())
	}

	createContextRequest := daga_login.CreateContext{
		Signature:       make([]byte, 32), // TODO openPGP etc..
		DagaNodes:       roster,
		SubscribersKeys: keys,
		ServiceID:       daga_login.ServiceID(uuid.Must(uuid.NewV4())),
	}
	createContextReply, err := s.CreateContext(&createContextRequest)
	require.NoError(t, err)
	require.NotZero(t, createContextReply)
	require.NotZero(t, createContextReply.Context)

	return createContextReply.Context, clients
}

// verify that Auth works for context created with CreateContext and Challenge received from PKClient, i.e: "full test"
func TestService_CreateContextAndPKclientAndAuth(t *testing.T) {
	local := onet.NewTCPTest(tSuite)
	hosts, roster, _ := local.GenTree(5, true)
	defer local.CloseAll()

	for _, s := range local.GetServices(hosts, DagaID) {
		log.Lvl2("Sending request to", s)

		// calls CreateContext
		context, clients := getTestContext(t, s.(*Service), roster, 5)

		// calls PKClient
		authMsg, err := daga.NewAuthenticationMessage(tSuite, context, clients[0], func(commits []kyber.Point) (daga.Challenge, error) {
			request := daga_login.PKclientCommitments{
				Commitments: commits,
				Context:     context,
			}
			reply, err := s.(*Service).PKClient(&request)
			require.NoError(t, err)
			return *reply.NetDecode(), nil
		})

		// calls Auth
		authRequest := daga_login.Auth(*daga_login.NetEncodeAuthenticationMessage(context, *authMsg))
		authReply, err := s.(*Service).Auth(&authRequest)
		require.NoError(t, err)
		require.NotZero(t, authReply)

		serverMsg, context := authReply.NetDecode()
		require.NoError(t, err)
		require.True(t, context.Equals(context), "context part of reply different than context of request")

		// verify / extract tag
		Tf, err := daga.GetFinalLinkageTag(tSuite, context, *serverMsg)
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
	context, err := service.validateAuthReq(&daga_login.Auth{
		Context:  daga_login.Context{},
		T0:       nil,
		SCommits: nil,
		Proof:    daga_login.ClientProof{},
	})
	require.Error(t, err, "should return error on empty req")
	require.Zero(t, context)
}

func TestValidateContextShouldErrorOnInvalidContext(t *testing.T) {
	local := onet.NewTCPTest(tSuite)
	hosts, roster, _ := local.GenTree(2, true)
	defer local.CloseAll()
	services := local.GetServices(hosts, DagaID)
	service := services[0].(*Service)

	badContext := daga_login.Context{
		Roster: roster,

		X: testing2.RandomPointSlice(5),
		Y: testing2.RandomPointSlice(9),
		H: testing2.RandomPointSlice(3), // len != 5 => invalid
		R: testing2.RandomPointSlice(8), // len != 9 => invalid

		ServiceID: daga_login.ServiceID(uuid.Must(uuid.NewV4())),
		ContextID: daga_login.ContextID(uuid.Must(uuid.NewV4())),
	}

	context, err := service.validateContext(badContext)
	require.Error(t, err, "should return error on invalid context")
	require.Zero(t, context)
}

func TestValidateContextShouldErrorOnEmptyRoster(t *testing.T) {
	service := &Service{}
	badContext := daga_login.Context{
		Roster: &onet.Roster{},

		X: testing2.RandomPointSlice(5),
		Y: testing2.RandomPointSlice(9),
		H: testing2.RandomPointSlice(5),
		R: testing2.RandomPointSlice(9),

		ServiceID: daga_login.ServiceID(uuid.Must(uuid.NewV4())),
		ContextID: daga_login.ContextID(uuid.Must(uuid.NewV4())),
	}
	context, err := service.validateContext(badContext)
	require.Error(t, err, "should return error on empty roster")
	require.Zero(t, context)

	badContext.Roster = &onet.Roster{List: make([]*network.ServerIdentity, 0, 5)}
	context, err = service.validateContext(badContext)
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
	overrideServicesSetup(services[0:0], dagaServers, *dummyContext)
	service := services[0].(*Service)
	service.Setup(service)

	// same roster but bullshit in daga.Context
	badNetContext := daga_login.Context{
		Roster: roster,

		X: testing2.RandomPointSlice(5),
		Y: testing2.RandomPointSlice(9),
		H: testing2.RandomPointSlice(5),
		R: testing2.RandomPointSlice(9),

		ServiceID: daga_login.ServiceID(uuid.Must(uuid.NewV4())),
		ContextID: daga_login.ContextID(uuid.Must(uuid.NewV4())),
	}
	context, err := service.validateContext(badNetContext)
	require.Error(t, err, "should return error on not accepted context")
	require.Zero(t, context)
}

func TestValidatePKClientReqShouldErrorOnNilRequest(t *testing.T) {
	service := &Service{}

	context, err := service.ValidatePKClientReq(nil)
	require.Error(t, err, "should return error on nil request")
	require.Zero(t, context)
}

func TestValidatePKClientReqShouldErrorOnEmptyOrBadlySizedCommitments(t *testing.T) {
	service := &Service{}

	context, err := service.ValidatePKClientReq(&daga_login.PKclientCommitments{
		Context: daga_login.Context{},
	})
	require.Error(t, err, "should return error on empty request")
	require.Zero(t, context)

	context, err = service.ValidatePKClientReq(&daga_login.PKclientCommitments{
		Context: daga_login.Context{
			H: testing2.RandomPointSlice(8),
		},
		Commitments: testing2.RandomPointSlice(12), // != 3*8
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
		Context: daga_login.Context{
			H: testing2.RandomPointSlice(8),
		},
		Commitments: testing2.RandomPointSlice(3 * 8),
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
