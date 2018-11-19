package service

/*

// TODO doc: implements DAGA, Deniable Anonymous Group Authentication Protocol

The service.go defines what to do for each API-call. This part of the service
runs on the cothority node.
*/

import (
	"errors"
	"fmt"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/dedis/student_18_daga/daga_login"
	"github.com/dedis/student_18_daga/daga_login/protocols/DAGA"
	"github.com/dedis/student_18_daga/daga_login/protocols/DAGAChallengeGeneration"
	"github.com/dedis/student_18_daga/daga_login/protocols/DAGAContextGeneration"
	"github.com/dedis/student_18_daga/sign/daga"
	"github.com/satori/go.uuid"
)

// Used for tests
var DagaID onet.ServiceID

func init() {
	var err error
	DagaID, err = onet.RegisterNewService(daga_login.ServiceName, newService)
	log.ErrFatal(err)
	network.RegisterMessages(Storage{}, daga_login.Context{}, daga_login.NetServer{})
}

// Service is our DAGA-service
// TODO doc + rename ?? (or QUESTION maybe rename only package DAGA.service DAGA.ChallengeGenerationProtocol DAGA.ServersProtocol etc.. or keep template organization what is the best ?)
type Service struct {
	// We need to embed the ServiceProcessor, so that incoming messages
	// are correctly handled.
	*onet.ServiceProcessor
	Storage *Storage               // TODO exported, needed by the tests ... but ... no other mean ? (I only see writing a dummy service that "embed"(cannot embed) service and override everything related to Storage but pffff)
	Setup   func(s *Service) error // see rationale described under `setupState`
}

// storageID reflects the data we're storing - we could store more
// than one structure.
var storageID = []byte("dagaStorage")

// Storage is used to save our data/state.
// always access Storage through the helpers/getters !
// QUESTION : separate storage from state or set "storage = state" ? (in my mind storage store backup of state but...)
type Storage struct { // exported.. needed by the tests..
	State
}

// helper to quickly validate CreateContext requests before proceeding further
func (s *Service) ValidateCreateContextReq(req *daga_login.CreateContext) error {
	// check that request is well formed
	if req.ServiceID == daga_login.ServiceID(uuid.Nil) || len(req.Signature) == 0 || len(req.SubscribersKeys) == 0 {
		return errors.New("validateCreateContextReq: malformed request")
	}

	// and that the request is indeed from the 3rd-party service admin  // TODO move inside acceptCreateContextRequest
	if err := authenticateRequest(req); err != nil {
		return errors.New("validateCreateContextReq: failed to authenticate 3rd-party service admin")
	}

	// check that we have a partnership with the 3rd-party service (or don't if we don't care / are an open server)
	if !s.acceptCreateContextRequest(req) {
		return errors.New("validateCreateContextReq: request not accepted by this server")
	}

	return nil
}

func (s *Service) acceptCreateContextRequest(req *daga_login.CreateContext) bool {
	// TODO check we are part of roster...

	if _, err := s.serviceState(req.ServiceID); err != nil {  // unknown service/1st time
		// TODO/FIXME for later check existing partnership/agreement, for now open access DAGA node.. accept everything
		// TODO => probably move this elsewhere, e.g at request authentication time in authenticateRequest or in caller

		// create/setup service state
		s.Storage.State[req.ServiceID] = &ServiceState{
			ID:            req.ServiceID,
			ContextStates: make(map[daga_login.ContextID]*ContextState),
			adminKey:      nil,  // TODO, openPGP, fetch key from keyserver
		}
	}

	return true
}

func authenticateRequest(req *daga_login.CreateContext) error {
	// FIXME use OpenPGP (or whatever.. or don't ...) + move elsewhere (maybe utils)

	// fetch public key from keyserver / trusted 3rd party

	// verify signature

	return nil
}

// API endpoint CreateContext, upon reception of a valid request,
// starts the context generation protocol, the current server/node will take the role of Leader
func (s *Service) CreateContext(req *daga_login.CreateContext) (*daga_login.CreateContextReply, error) {
	// setup if not already done
	if err := s.Setup(s); err != nil {
		return nil, errors.New("CreateContext: " + err.Error())
	}

	// verify that submitted request is valid and accepted by our node
	if err := s.ValidateCreateContextReq(req); err != nil {
		return nil, errors.New("CreateContext: " + err.Error())
	}

	// start context generation protocol
	if contextGeneration, err := s.newDAGAContextGenerationProtocol(req); err != nil {
		return nil, errors.New("CreateContext: " + err.Error())
	} else {
		if context, dagaServer, err := contextGeneration.WaitForResult(); err != nil {
			return nil, err
		} else {
			// FIXME here publish to byzcoin etc.. (and decide what by who.., IMO it's to the 3rd party service responsibility to publish the context)
			// FIXME and if we decide (why ? "convenience" ?) to store the dagaServer in byzcoin too => need to encrypt it (using which key ? => node's key from private.toml)

			// store in local state/cache
			serviceState, err := s.serviceState(context.ServiceID)
			if err != nil {  // unknown service/1st time, create service state
				log.Panic("CreateContext: something wrong, 3rd-party service state not present in DAGA service's storage/state")
			}
			if _, err := serviceState.contextState(context.ID); err == nil {
				return nil, fmt.Errorf("CreateContext: ... seems that a context with same ID (%s) is already existing", context.ID)
			}
			serviceState.ContextStates[context.ID] = &ContextState{
				Context: context,
				DagaServer: *daga_login.NetEncodeServer(dagaServer),
			}

			return &daga_login.CreateContextReply{
				Context: context,
			}, nil
		}
	}
}

// helper to quickly validate Auth requests before proceeding further
func (s Service) validateAuthReq(req *daga_login.Auth) (daga.Server, error) {
	// validate initial tag and commitments
	if req == nil || len(req.SCommits) == 0 || req.T0 == nil {
		return nil, errors.New("validateAuthReq: nil or empty request")
	}
	// TODO idea/optimisation (for when I'll rewrite DAGA API...) validate proof here to avoid spawning a protocol for nothing
	// validate context
	return s.validateContext(req.Context)
}

// API endpoint Auth,
// starts the server's protocol (daga 4.3.6)
func (s *Service) Auth(req *daga_login.Auth) (*daga_login.AuthReply, error) {
	// setup if not already done
	if err := s.Setup(s); err != nil {
		return nil, errors.New("Auth: " + err.Error())
	}

	// verify that submitted request is valid and accepted by our node
	dagaServer, err := s.validateAuthReq(req)
	if err != nil {
		return nil, errors.New("Auth: " + err.Error())
	}

	// start daga server's protocol
	if daga, err := s.newDAGAServerProtocol(req, dagaServer); err != nil {
		return nil, errors.New("Auth: " + err.Error())
	} else {
		serverMsg, err := daga.WaitForResult()
		netServerMsg := daga_login.NetEncodeServerMessage(req.Context, &serverMsg)
		// FIXME : return Tag + sigs instead of final servermsg (another legacy of previous code...rhaaa => need to refactor things again => min 2 days..probably more)
		return (*daga_login.AuthReply)(netServerMsg), err
	}
}

// helper that check if received context is valid, (fully populated, accepted, etc..)
// returns the daga.Server used to work with this context, nil if ok to proceed, or nil, err otherwise
func (s Service) validateContext(reqContext daga_login.Context) (daga.Server, error) {
	if len(reqContext.Roster.List) == 0 || reqContext.ID == daga_login.ContextID(uuid.Nil) || reqContext.ServiceID == daga_login.ServiceID(uuid.Nil) {
		return nil, errors.New("validateContext: empty Context")
	}

	if err := daga.ValidateContext(reqContext); err != nil {
		return nil, err
	}

	if dagaServer, err := s.acceptContext(reqContext); err != nil {
		return nil, errors.New("validateContext: auth. context part of the request is not accepted by this server: " + err.Error())
	} else {
		return dagaServer, nil
	}
}

// helper to check if we accept the context that was sent part of the Auth/PKClient request,
// if the context is accepted, returns the corresponding daga.Server (needed to process requests under the context)
func (s Service) acceptContext(reqContext daga_login.Context) (daga.Server, error) {
	if serviceState, err := s.serviceState(reqContext.ServiceID); err != nil {
		return nil, errors.New("acceptContext: failed to retrieve 3rd-party service related state: " + err.Error())
	} else if contextState, err := serviceState.contextState(reqContext.ID); err != nil {
		return nil, errors.New("acceptContext: failed to retrieve context related state: " + err.Error())
	} else {
		if contextState.Context.Equals(reqContext) { // TODO/FIXME see equals comments, use another function or implement logic here
			return contextState.DagaServer.NetDecode()
		} else {
			return nil, errors.New("acceptContext: context not accepted")
		}
	}
}

// helper to validate PKClient requests before proceeding further
func (s Service) ValidatePKClientReq(req *daga_login.PKclientCommitments) (daga.Server, error) {

	// validate PKClient commitments
	if req == nil {
		return nil, errors.New("validatePKClientReq: nil request")
	}
	if len(req.Commitments) == 0 || len(req.Commitments) != len(req.Context.H)*3 {
		return nil, errors.New("validatePKClientReq: empty or wrongly sized commitments")
	}

	// validate context
	return s.validateContext(req.Context)
}

// API endpoint PKClient, upon reception of a valid request,
// starts the challenge generation protocol, the current server/node will take the role of Leader
func (s *Service) PKClient(req *daga_login.PKclientCommitments) (*daga_login.PKclientChallenge, error) {
	// setup service state if not already done
	if err := s.Setup(s); err != nil {
		return nil, errors.New("PKClient: " + err.Error())
	}
	// verify that submitted request is valid and accepted by our node
	dagaServer, err := s.ValidatePKClientReq(req)
	if err != nil {
		return nil, errors.New("PKClient: " + err.Error())
	}

	// FIXME always use context picked by our own mean and check that context in req is the exact same !!

	// start challenge generation protocol
	if challengeGeneration, err := s.newDAGAChallengeGenerationProtocol(req, dagaServer); err != nil {
		return nil, errors.New("PKClient: " + err.Error())
	} else {
		challenge, err := challengeGeneration.WaitForResult()
		return (*daga_login.PKclientChallenge)(&challenge), err
	}
}

// function called to initialize and start a new DAGA (Server's) protocol where current node takes a "Leader" role
func (s *Service) newDAGAServerProtocol(req *daga_login.Auth, dagaServer daga.Server) (*DAGA.Protocol, error) {
	// TODO/FIXME see if always ok to use user provided roster... (we already check auth. context)

	// build tree with leader as root
	roster := req.Context.Roster
	tree := roster.GenerateNaryTreeWithRoot(len(roster.List)-1, s.ServerIdentity())
	// QUESTION would be convenient to have a ring topology out of tree (each node as one and only one parent AND one and only one child)
	// => what can go wrong if I do that ? (would solve the "multiple daga server and context issues") while being nice and readable (simplify protocol code, see sendToNextNode)

	// create and setup protocol instance
	pi, err := s.CreateProtocol(DAGA.Name, tree)
	if err != nil {
		return nil, errors.New("failed to create " + DAGA.Name + " protocol: " + err.Error())
	}
	dagaProtocol := pi.(*DAGA.Protocol)
	dagaProtocol.LeaderSetup(*(*daga_login.NetAuthenticationMessage)(req), dagaServer)

	// start
	if err = dagaProtocol.Start(); err != nil {
		return nil, fmt.Errorf("failed to start %s protocol: %s", DAGA.Name, err)
	}
	log.Lvlf3("service started %s protocol, waiting for completion", DAGA.Name)
	return dagaProtocol, nil
}

// function called to initialize and start a new DAGAChallengeGeneration protocol where current node takes a Leader role
func (s *Service) newDAGAChallengeGenerationProtocol(req *daga_login.PKclientCommitments, dagaServer daga.Server) (*DAGAChallengeGeneration.Protocol, error) {
	// build tree with leader as root
	roster := req.Context.Roster
	// pay attention to the fact that for the protocol to work the tree needs to be correctly shaped !!
	// protocol assumes that all other nodes are direct children of leader (use aggregation before calling some handlers)
	tree := roster.GenerateNaryTreeWithRoot(len(roster.List)-1, s.ServerIdentity())

	// create and setup protocol instance
	pi, err := s.CreateProtocol(DAGAChallengeGeneration.Name, tree)
	if err != nil {
		return nil, errors.New("failed to create " + DAGAChallengeGeneration.Name + " protocol: " + err.Error())
	}
	challengeGeneration := pi.(*DAGAChallengeGeneration.Protocol)
	challengeGeneration.LeaderSetup(*req, dagaServer)

	// start
	if err = challengeGeneration.Start(); err != nil {
		return nil, fmt.Errorf("failed to start %s protocol: %s", DAGAChallengeGeneration.Name, err)
	}
	log.Lvlf3("service started %s protocol, waiting for completion", DAGAChallengeGeneration.Name)
	return challengeGeneration, nil
}

// function called to initialize and start a new DAGAContextGeneration protocol where current node takes a Leader role
func (s *Service) newDAGAContextGenerationProtocol(req *daga_login.CreateContext) (*DAGAContextGeneration.Protocol, error) {

	// build tree with leader as root
	roster := req.DagaNodes
	// pay attention to the fact that, for the protocol to work, the tree needs to be correctly shaped !!
	// protocol assumes that all other nodes are direct children of leader (use aggregation before calling some handlers)
	tree := roster.GenerateNaryTreeWithRoot(len(roster.List)-1, s.ServerIdentity())

	// create and setup protocol instance
	pi, err := s.CreateProtocol(DAGAContextGeneration.Name, tree)
	if err != nil {
		return nil, errors.New("failed to create " + DAGAContextGeneration.Name + " protocol: " + err.Error())
	}
	contextGeneration := pi.(*DAGAContextGeneration.Protocol)
	contextGeneration.LeaderSetup(req)

	// start
	if err = contextGeneration.Start(); err != nil {
		return nil, fmt.Errorf("failed to start %s protocol: %s", DAGAContextGeneration.Name, err)
	}
	log.Lvlf3("service started %s protocol, waiting for completion", DAGAContextGeneration.Name)
	return contextGeneration, nil
}

// NewProtocol is called upon reception of a Protocol's first message when Onet needs
// to instantiate the protocol. A Service is expected to manually create
// the ProtocolInstance it is using. So this method will be potentially called on all nodes of a Tree (except the root, since it is
// the one starting the protocols) to generate the PI on those other nodes.
// if it returns nil, nil then the default NewProtocol is called (the one defined in protocol)
// FIXME outdated documentation in template
// TODO share code between protocols (same structure, cast to new interface and call ChildSetup on it ?)
// TODO and if like now the setup becomes more and more similar to the one for Leader, consider making small modifications to get rid of this NewProtocol, return nil, nil and have everything in protocol if possible
func (s *Service) NewProtocol(tn *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl3("received protocol msg, instantiating new protocol instance of " + tn.ProtocolName())
	// setup if not already done
	if err := s.Setup(s); err != nil {
		return nil, errors.New("NewProtocol: " + err.Error())
	}
	switch tn.ProtocolName() {
	case DAGAChallengeGeneration.Name:
		pi, err := DAGAChallengeGeneration.NewProtocol(tn)
		if err != nil {
			return nil, err
		}
		challengeGeneration := pi.(*DAGAChallengeGeneration.Protocol)
		challengeGeneration.ChildSetup(s.ValidatePKClientReq)
		return challengeGeneration, nil
	case DAGA.Name:
		pi, err := DAGA.NewProtocol(tn)
		if err != nil {
			return nil, err
		}
		dagaServerProtocol := pi.(*DAGA.Protocol)
		dagaServerProtocol.ChildSetup(s.validateContext)  // TODO same as above/below validate full request
		return dagaServerProtocol, nil
	case DAGAContextGeneration.Name:
		pi, err := DAGAContextGeneration.NewProtocol(tn)
		if err != nil {
			return nil, err
		}
		contextGeneration := pi.(*DAGAContextGeneration.Protocol)
		contextGeneration.ChildSetup(s.ValidateCreateContextReq)
		return contextGeneration, nil
	default:
		log.Panic("NewProtocol: protocol not implemented/known")
	}
	return nil, errors.New("should not be reached")
}

// saves all data/state.
func (s *Service) save() {
	err := s.Save(storageID, s.Storage)
	if err != nil {
		log.Error("Couldn't save service data: ", err)
	}
}

// Tries to load the configuration and updates the data in the service
// if it finds a valid config-file
//
// TODO FIXME see if can redesign this mess later when we have a bootstrap method
// rationale for not being a method anymore: to do testing more easily need ways to swap the function with a stub
// + since it was called in newService previously => called from init (even in the test => crash) => "solution" don't call it at setup time
// but when endpoint called and no-op if already setup
func setupState(s *Service) error {
	if s.Storage == nil {
		s.Storage = &Storage{}
		msg, err := s.Load(storageID)
		if err != nil {
			return err
		}
		if msg == nil {
			// first time or nothing, load from permanent storage files
			// TODO/FIXME/QUESTION if makes sense
			return nil
		} else {
			var ok bool
			s.Storage, ok = msg.(*Storage)
			if !ok {
				return errors.New("tryLoad: data of wrong type")
			}
			return nil
		}
	}
	return nil
}

func (s *Service) serviceState(sid daga_login.ServiceID) (*ServiceState, error) {
	if sid == daga_login.ServiceID(uuid.Nil) {
		return nil, errors.New("serviceState: Nil/Zero ID")
	}
	if serviceState, ok := s.Storage.State[sid]; !ok {
		return nil, fmt.Errorf("serviceState: unknown service ID: %v", sid)
	} else {
		return serviceState, nil
	}
}

// newService receives the context that holds information about the node it's
// running on. Saving and loading can be done using the context. The data will
// be stored in memory for tests and simulations, and on disk for real deployments.
func newService(c *onet.Context) (onet.Service, error) {
	s := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
	}
	if err := s.RegisterHandlers(s.Auth, s.PKClient, s.CreateContext); err != nil {
		return nil, errors.New("Couldn't register service's API handlers/messages: " + err.Error())
	}
	s.Setup = setupState
	return s, nil
}
