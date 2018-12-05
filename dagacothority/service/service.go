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
	"github.com/dedis/student_18_daga/dagacothority"
	"github.com/dedis/student_18_daga/dagacothority/protocols/DAGA"
	"github.com/dedis/student_18_daga/dagacothority/protocols/dagachallengegeneration"
	"github.com/dedis/student_18_daga/dagacothority/protocols/dagacontextgeneration"
	"github.com/dedis/student_18_daga/sign/daga"
	"github.com/satori/go.uuid"
)

// DagaID ID of the daga service in onet, exported because needed by the tests
var DagaID onet.ServiceID

func init() {
	var err error
	DagaID, err = onet.RegisterNewService(dagacothority.ServiceName, newService)
	log.ErrFatal(err)
	network.RegisterMessages(Storage{}, dagacothority.Context{}, dagacothority.NetServer{})
}

// Service is our DAGA-service
// TODO doc + rename ?? (or QUESTION maybe rename only package DAGA.service DAGA.ChallengeGenerationProtocol DAGA.ServersProtocol etc.. or keep template organization what is the best ?)
type Service struct {
	// We need to embed the ServiceProcessor, so that incoming messages
	// are correctly handled.
	*onet.ServiceProcessor
	Storage *Storage               // QUESTION exported, needed by the tests ... but ... no other mean ? (I only see writing a dummy service that "embed"(cannot embed) service and override everything related to Storage but ...)
	Setup   func(s *Service) error // see rationale described under `setupState`
}

// storageID reflects the data we're storing - we could store more
// than one structure.
var storageID = []byte("dagaStorage")

// Storage is used to save our data/state.
// always access Storage's state through the helpers/getters !
type Storage struct { // exported.. needed by the tests..
	State
}

// ValidateCreateContextReq is an helper to quickly validate CreateContext requests before proceeding further
func (s *Service) ValidateCreateContextReq(req *dagacothority.CreateContext) error {
	// check that request is well formed
	// TODO check we are part of roster...
	if req.ServiceID == dagacothority.ServiceID(uuid.Nil) || len(req.Signature) == 0 || len(req.SubscribersKeys) == 0 {
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

	// if 3rd-party related state not present/first time, create/setup it
	s.Storage.State.createIfNotExisting(req.ServiceID)

	return nil
}

func (s *Service) acceptCreateContextRequest(req *dagacothority.CreateContext) bool {
	if _, err := s.serviceState(req.ServiceID); err != nil { // unknown service/1st time
		// for now open access DAGA node, accept everything
		// TODO for later search for existing partnership/agreement,
	} else {
		// FIXME check context not already existing
	}
	return true
}

// only authorized people (such as admins of 3rd-party services (RP) who have an agreement, implicit or not with the admin of the daga node(s))
// should be able to trigger the creation of new contexts.
func authenticateRequest(req *dagacothority.CreateContext) error {
	// FIXME use OpenPGP (or whatever.. or don't ...) + move elsewhere (maybe utils)

	// fetch public key from keyserver / trusted 3rd party

	// verify signature

	// TODO seems that Linus is working on a an authentication/authorization service/framework => why not using it when done
	// https://github.com/dedis/cothority/pull/1050/commits/770631ca43a5e02a43825a7837b9f8132d8798ad

	return nil
}

// CreateContext is an API endpoint, upon reception of a valid request,
// starts the context generation protocol, the current server/node will take the role of Leader
func (s *Service) CreateContext(req *dagacothority.CreateContext) (*dagacothority.CreateContextReply, error) {
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
			return nil, errors.New("CreateContext: " + err.Error())
		} else {
			if err := s.startServingContext(context, dagaServer); err != nil {
				return nil, errors.New("CreateContext: " + err.Error())
			}
			return &dagacothority.CreateContextReply{
				Context: context,
			}, nil
		}
	}
}

// helper to quickly validate Auth requests before proceeding further
func (s Service) validateAuthReq(req *dagacothority.Auth) (daga.Server, error) {
	// validate initial tag and commitments
	if req == nil || len(req.SCommits) == 0 || req.T0 == nil {
		return nil, errors.New("validateAuthReq: nil or empty request")
	}
	// TODO idea/optimisation (for when I'll rewrite DAGA API...) validate proof here to avoid spawning a protocol for nothing
	// validate context
	return s.validateContext(req.Context)
}

// Auth is an API endpoint,
// starts the server's protocol (daga 4.3.6) to authenticate an user with the help of its auth. request
func (s *Service) Auth(req *dagacothority.Auth) (*dagacothority.AuthReply, error) {
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
		netServerMsg := dagacothority.NetEncodeServerMessage(req.Context, &serverMsg)
		// FIXME : return Tag + sigs instead of final servermsg (another legacy of previous code...rhaaa => need to refactor things again => min 2 days..probably more)
		return (*dagacothority.AuthReply)(netServerMsg), err
	}
}

// helper that check if received context is valid, (fully populated, accepted, etc..)
// returns the daga.Server used to work with this context, nil if ok to proceed, or nil, err otherwise
func (s Service) validateContext(reqContext dagacothority.Context) (daga.Server, error) {
	if len(reqContext.Roster.List) == 0 || reqContext.ContextID == dagacothority.ContextID(uuid.Nil) || reqContext.ServiceID == dagacothority.ServiceID(uuid.Nil) {
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
func (s Service) acceptContext(reqContext dagacothority.Context) (daga.Server, error) {
	// if context is accepted => we took part in the context generation && 3rd-party service is accepted => node has kept something in its state
	if serviceState, err := s.serviceState(reqContext.ServiceID); err != nil {
		return nil, errors.New("acceptContext: failed to retrieve 3rd-party service related state: " + err.Error())
	} else if contextState, err := serviceState.contextState(reqContext.ContextID); err != nil {
		return nil, errors.New("acceptContext: failed to retrieve context related state: " + err.Error())
	} else {
		// TODO/ and/or/maybe verify context signature (should not be necessary if integrity preserved/protected by equals/hash and we have a trusted copy somewhere)
		// TODO => FIXME see equals comments, depend on what features we want, see later, use another function or implement logic here
		if contextState.Context.Equals(reqContext) {
			return contextState.DagaServer.NetDecode()
		} else {
			return nil, errors.New("acceptContext: context not accepted")
		}
	}
}

// ValidatePKClientReq is an helper used to validate PKClient requests before proceeding further
func (s Service) ValidatePKClientReq(req *dagacothority.PKclientCommitments) (daga.Server, error) {

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

// PKClient is an API endpoint, upon reception of a valid request,
// starts the challenge generation protocol, the current server/node will take the role of Leader
func (s *Service) PKClient(req *dagacothority.PKclientCommitments) (*dagacothority.PKclientChallenge, error) {
	// setup service state if not already done
	if err := s.Setup(s); err != nil {
		return nil, errors.New("PKClient: " + err.Error())
	}
	// verify that submitted request is valid and accepted by our node
	dagaServer, err := s.ValidatePKClientReq(req)
	if err != nil {
		return nil, errors.New("PKClient: " + err.Error())
	}

	// TODO remember for later, always use context picked by our own mean or / and check that context in req is the exact same !! => see remarks in acceptContext

	// start challenge generation protocol
	if challengeGeneration, err := s.newDAGAChallengeGenerationProtocol(req, dagaServer); err != nil {
		return nil, errors.New("PKClient: " + err.Error())
	} else {
		challenge, err := challengeGeneration.WaitForResult()
		return dagacothority.NetEncodeChallenge(challenge), err
	}
}

// function called to initialize and start a new DAGA (Server's) protocol where current node takes a "Leader" role
func (s *Service) newDAGAServerProtocol(req *dagacothority.Auth, dagaServer daga.Server) (*DAGA.Protocol, error) {
	// TODO/FIXME see if always ok to use user provided roster... (we already check auth. context)
	// FIXME probably want to add roster to signed/authenticated data at context creation time

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
	dagaProtocol.LeaderSetup(*req, dagaServer)

	// start
	if err = dagaProtocol.Start(); err != nil {
		return nil, fmt.Errorf("failed to start %s protocol: %s", DAGA.Name, err)
	}
	log.Lvlf3("service started %s protocol, waiting for completion", DAGA.Name)
	return dagaProtocol, nil
}

// function called to initialize and start a new dagachallengegeneration protocol where current node takes a Leader role
func (s *Service) newDAGAChallengeGenerationProtocol(req *dagacothority.PKclientCommitments, dagaServer daga.Server) (*dagachallengegeneration.Protocol, error) {
	// build tree with leader as root
	roster := req.Context.Roster
	// pay attention to the fact that for the protocol to work the tree needs to be correctly shaped !!
	// protocol assumes that all other nodes are direct children of leader (use aggregation before calling some handlers)
	tree := roster.GenerateNaryTreeWithRoot(len(roster.List)-1, s.ServerIdentity())

	// create and setup protocol instance
	pi, err := s.CreateProtocol(dagachallengegeneration.Name, tree)
	if err != nil {
		return nil, errors.New("failed to create " + dagachallengegeneration.Name + " protocol: " + err.Error())
	}
	challengeGeneration := pi.(*dagachallengegeneration.Protocol)
	challengeGeneration.LeaderSetup(*req, dagaServer)

	// start
	if err = challengeGeneration.Start(); err != nil {
		return nil, fmt.Errorf("failed to start %s protocol: %s", dagachallengegeneration.Name, err)
	}
	log.Lvlf3("service started %s protocol, waiting for completion", dagachallengegeneration.Name)
	return challengeGeneration, nil
}

// function called to initialize and start a new dagacontextgeneration protocol where current node takes a Leader role
func (s *Service) newDAGAContextGenerationProtocol(req *dagacothority.CreateContext) (*dagacontextgeneration.Protocol, error) {

	// build tree with leader as root
	roster := req.DagaNodes
	// pay attention to the fact that, for the protocol to work, the tree needs to be correctly shaped !!
	// protocol assumes that all other nodes are direct children of leader (use aggregation before calling some handlers)
	tree := roster.GenerateNaryTreeWithRoot(len(roster.List)-1, s.ServerIdentity())

	// create and setup protocol instance
	pi, err := s.CreateProtocol(dagacontextgeneration.Name, tree)
	if err != nil {
		return nil, errors.New("failed to create " + dagacontextgeneration.Name + " protocol: " + err.Error())
	}
	contextGeneration := pi.(*dagacontextgeneration.Protocol)
	contextGeneration.LeaderSetup(req)

	// start
	if err = contextGeneration.Start(); err != nil {
		return nil, fmt.Errorf("failed to start %s protocol: %s", dagacontextgeneration.Name, err)
	}
	log.Lvlf3("service started %s protocol, waiting for completion", dagacontextgeneration.Name)
	return contextGeneration, nil
}

// NewProtocol is called upon reception of a Protocol's first message when Onet needs
// to instantiate the protocol. A Service is expected to manually create
// the ProtocolInstance it is using. So this method will be potentially called on all nodes of a Tree (except the root, since it is
// the one starting the protocols) to generate the PI on those other nodes.
// if it returns nil, nil then the default NewProtocol is called (the one defined in protocol)
// FIXME outdated documentation in cothority_template => propose replacement
// TODO share code between protocols (same structure, cast to new interface and call ChildSetup on it ?)
// TODO and if like now the setup becomes more and more similar to the one for Leader, consider making small modifications to get rid of this NewProtocol, return nil, nil and have everything in protocol if possible
func (s *Service) NewProtocol(tn *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl3("received protocol msg, instantiating new protocol instance of " + tn.ProtocolName())
	// setup if not already done
	if err := s.Setup(s); err != nil {
		return nil, errors.New("NewProtocol: " + err.Error())
	}
	switch tn.ProtocolName() {
	case dagachallengegeneration.Name:
		pi, err := dagachallengegeneration.NewProtocol(tn)
		if err != nil {
			return nil, err
		}
		challengeGeneration := pi.(*dagachallengegeneration.Protocol)
		challengeGeneration.ChildSetup(s.ValidatePKClientReq)
		return challengeGeneration, nil
	case DAGA.Name:
		pi, err := DAGA.NewProtocol(tn)
		if err != nil {
			return nil, err
		}
		dagaServerProtocol := pi.(*DAGA.Protocol)
		dagaServerProtocol.ChildSetup(s.validateContext) // TODO same as above/below validate full request vs only context
		return dagaServerProtocol, nil
	case dagacontextgeneration.Name:
		pi, err := dagacontextgeneration.NewProtocol(tn)
		if err != nil {
			return nil, err
		}
		contextGeneration := pi.(*dagacontextgeneration.Protocol)
		contextGeneration.ChildSetup(s.ValidateCreateContextReq, s.startServingContext)
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
// + since it was called in newService previously => called from init (even in the test => crash) => "solution" don't call it at newService time
// but when endpoints called and no-op if already setup
func setupState(s *Service) error {
	if s.Storage == nil {
		s.Storage = &Storage{
			State: NewState(),
		}
		msg, err := s.Load(storageID)
		if err != nil {
			return err
		}
		if msg == nil {
			// first time or nothing, load from permanent storage files maybe..FIXME from byzcoin ? later..
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

// returns the 3rd-party related state or an error if 3rd-party service unknown.
// !always use it to read service's state, (direct access to the storage's state map can lead to race conditions
// since the storage can be accessed/updated from multiple goroutines (protocol instances))!
func (s *Service) serviceState(sid dagacothority.ServiceID) (*ServiceState, error) {
	if sid == dagacothority.ServiceID(uuid.Nil) {
		return nil, errors.New("serviceState: Nil/Zero ID")
	}
	serviceState, err := s.Storage.State.get(sid)
	if err != nil {
		return nil, errors.New("serviceState: " + err.Error())
	}
	return serviceState, nil
}

// updates the 3rd-party related state, safe wrapper for write access to the Storage.state "map"
// !always use it to write service's state (add a ServiceState), (direct access to the storage's state map can lead to race conditions
// since the storage can be accessed/updated from multiple goroutines (protocol instances))!
func (s *Service) setServiceState(key dagacothority.ServiceID, value *ServiceState) error {
	if key == dagacothority.ServiceID(uuid.Nil) || value == nil {
		return errors.New("serviceState: Nil/Zero ID/key or value")
	}
	s.Storage.State.Set(key, value)
	return nil
}

// starts serving (accepting requests related to) `context` using `dagaServer`
func (s *Service) startServingContext(context dagacothority.Context, dagaServer daga.Server) error {

	// FIXME here publish to byzcoin etc.. (and decide what should be done by who.., IMO it's to the 3rd party service responsibility to publish the context)
	// FIXME and if no matter my opinion still want to publish from here, do it only from Leader (currently this is called at all nodes at the end of context generation protocol)
	// FIXME and if we decide (why ? "convenience" ?) to store the dagaServer in byzcoin too => need to encrypt it (using which key ? => node's key from private.toml)
	// (if that makes sense, if cannot already be protected by other features of byzcoin)

	// store in local state/cache
	serviceState, err := s.serviceState(context.ServiceID)
	if err != nil {
		log.Panic("startServingContext: something wrong, 3rd-party service related state not present in DAGA service's storage/state")
	}
	if _, err := serviceState.contextState(context.ContextID); err == nil {
		return fmt.Errorf("startServingContext: ... seems that a context with same ID (%s) is already existing", context.ContextID)
	}
	serviceState.ContextStates[context.ContextID] = &ContextState{
		Context:    context,
		DagaServer: *dagacothority.NetEncodeServer(dagaServer),
	}
	return nil
}

// newService receives the context that holds information about the node it's
// running on. Saving and loading can be done using the context. The data will
// be stored in memory for tests and simulations, and on disk for real deployments (QUESTION how ?? I'd like to..).
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
