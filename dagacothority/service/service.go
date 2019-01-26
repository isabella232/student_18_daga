package service

//Implements DAGA (Deniable Anonymous Group Authentication) in the cothority framework.
//
//The service.go defines what to do for each API-call. This part of the service
//runs on the cothority node.


import (
	"errors"
	"fmt"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/dedis/student_18_daga/dagacothority"
	"github.com/dedis/student_18_daga/dagacothority/protocols/dagaauth"
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
type Service struct {
	// We need to embed the ServiceProcessor, so that incoming messages
	// are correctly handled.
	*onet.ServiceProcessor
	Storage *Storage
}

// storageID reflects the data we're storing - we could store more
// than one structure.
var storageID = []byte("dagaStorage")

// Storage is used to save our data/state.
// always access Storage's state through the helpers/getters !
type Storage struct {
	State
}

// ValidateCreateContextReq is an helper to quickly validate CreateContext requests before proceeding further
func (s *Service) ValidateCreateContextReq(req *dagacothority.CreateContext) error {
	// check that request is well formed
	// TODO check we are part of roster...but don't see this being done in other cothority projects, so ?
	if req.ServiceID == dagacothority.ServiceID(uuid.Nil) || len(req.Signature) == 0 || len(req.SubscribersKeys) == 0 {
		return errors.New("validateCreateContextReq: malformed request")
	}

	// and that the request is indeed from the 3rd-party service admin
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
	// for now open access DAGA node, accept everything
	// TODO for later offer the option to search somewhere/somehow for existing partnership/agreement or input from nodes' admin (via email sms code etc..)
	//  can even be backed in the authentication step, e.g. if we use "~recursively" DAGA, we can define administratively/offline a
	//  context whose members are the people that have a partnership/agreement with the daga conode admin that allow them to create contexts, (similar to authenticated darcs)
	//  then a running cothority (serving the context) and containing the conode, authenticates the request
	//  => the node is convinced that the "remote now anon 3rd-party service admin" has the right to create new contexts
	//  => (+) KISS, can use only DAGA, no need to use alien protocols and things like openPGP or DARC management etc..
	//  => (+) ~"eat your own food" preserve 3rd-party admin privacy, don't throw out of the window our own goals and advices on the separation of authentication and identification etc..
	//  => the thing now becomes: offering ways to manage the partnerships and setup those partnership contexts.
	//  chicken and egg problem but now we can decide to bootstrap them differently using whatever means we want
	//  (a cli app ? + administrative context loaded from known location at setup time)
	return true
}

// only authorized people (such as admins of 3rd-party services (RP) who have an agreement, implicit or not with the admin of the daga node(s))
// should be able to trigger the creation of new contexts.
func authenticateRequest(req *dagacothority.CreateContext) error {
	// TODO use OpenPGP (or whatever.. see below) f
	//  fetch public key from keyserver / TRUSTED 3rd party
	//  verify signature.
	//  seems that Linus is working on a an authentication/authorization service/framework => why not using it when done
	//  https://github.com/dedis/cothority/pull/1050/commits/770631ca43a5e02a43825a7837b9f8132d8798ad
	//  + what about darc
	//  + why the new authentication service if darc exists ?
	//  (or phrased differently why DARC stands for distributed ACCESS right CONTROL if there are no authentication? authorization needs authentication in my mind)
	//  => use darc AND the future new auth service to authenticate and authorize requests
	//  or use DAGA (or build the new cothority auth. service with daga !?)
	//  and this is a bit a chicken and egg problem but DAGA is exactly that, a distributed authentication service
	//  => why not use it to anonymously authenticate remote admin as being member of a context containing the keys of the
	//  admins that have a partnership with the node admin !!
	//  => full anon access control strategy, auth^2, see comment in acceptCreateContextRequest
	//  or offer multiple ways including widely accepted and deployed ones (we don't force the users/RP to use our technologies),
	return nil
}

// CreateContext is an API endpoint, upon reception of a valid request,
// starts the context generation protocol, the current server/node will take the role of "Leader".
// on success the cothority will start serving (accepting auth. requests under) the newly created daga context.
func (s *Service) CreateContext(req *dagacothority.CreateContext) (*dagacothority.CreateContextReply, error) {

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
	// TODO idea/"optimisation" (for when someone rewrite sign/daga API...) maybe validate proof here to avoid spawning a protocol for nothing
	// validate context
	return s.validateContext(req.Context)
}

// Auth is an API endpoint, upon reception of a valid request,
// starts the server's protocol (daga paper 4.3.6) to authenticate an user, the current server/node will take the role of "Leader"
func (s *Service) Auth(req *dagacothority.Auth) (*dagacothority.AuthReply, error) {

	// verify that submitted request is valid and accepted by our node
	dagaServer, err := s.validateAuthReq(req)
	if err != nil {
		return nil, errors.New("Auth: " + err.Error())
	}

	// start daga server's protocol
	if dagaProtocol, err := s.newDAGAServerProtocol(req, dagaServer); err != nil {
		return nil, errors.New("Auth: " + err.Error())
	} else {
		serverMsg, err := dagaProtocol.WaitForResult()
		netServerMsg := dagacothority.NetEncodeServerMessage(req.Context, &serverMsg)
		// TODO : return Tag + sigs instead of final servermsg (legacy of previous code)
		//  do it when refactoring sign/daga server code/API
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
	if serviceState, err := s.serviceState(reqContext.ServiceID); err != nil {
		return nil, errors.New("acceptContext: failed to retrieve 3rd-party service related state: " + err.Error())
	} else if contextState, err := serviceState.contextState(reqContext.ContextID); err != nil {
		return nil, errors.New("acceptContext: failed to retrieve context related state: " + err.Error())
	} else {
		// TODO verify only context signatures
		//  (should not be necessary if ~integrity preserved/protected by equals/hash and we have a trusted copy somewhere)
		//  but we can rely only on signature and then don't need to store the context in state (authenticity + integrity protected)
		//  a node serve a context if it recognize is own signature, if signature present node has participated in creation etc...
		//  (+) less or no state, don't need to protect state etc..
		//  => see equals comments, depend on what features we want, see later when context evolution implemented.
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
// starts the challenge generation protocol, the current server/node will take the role of "Leader"
func (s *Service) PKClient(req *dagacothority.PKclientCommitments) (*dagacothority.PKclientChallenge, error) {

	// verify that submitted request is valid and accepted by our node
	dagaServer, err := s.ValidatePKClientReq(req)
	if err != nil {
		return nil, errors.New("PKClient: " + err.Error())
	}

	// start challenge generation protocol
	if challengeGeneration, err := s.newDAGAChallengeGenerationProtocol(req, dagaServer); err != nil {
		return nil, errors.New("PKClient: " + err.Error())
	} else {
		challenge, err := challengeGeneration.WaitForResult()
		return dagacothority.NetEncodeChallenge(challenge), err
	}
}

// traffic is an API endpoint used only to gather stats/data (used in simulations), upon reception of a valid request,
// answer with the current total rx/tx
func (s *Service) traffic(req *dagacothority.Traffic) (*dagacothority.TrafficReply, error) {
	//counterIO := s.CounterIO()
	//return &dagacothority.TrafficReply{
	//	Rx: counterIO.Rx(),
	//	Tx: counterIO.Tx(),
	//}, nil
	return nil, errors.New("!uncomment function body and patch onet!")
}

// function called to initialize and start a new DAGA (Server's) protocol where current node takes a "Leader" role
func (s *Service) newDAGAServerProtocol(req *dagacothority.Auth, dagaServer daga.Server) (*dagaauth.Protocol, error) {
	// build tree with leader as root
	roster := req.Context.Roster
	tree := roster.GenerateNaryTreeWithRoot(len(roster.List)-1, s.ServerIdentity())

	// create and setup protocol instance
	pi, err := s.CreateProtocol(dagaauth.Name, tree)
	if err != nil {
		return nil, errors.New("failed to create " + dagaauth.Name + " protocol: " + err.Error())
	}
	dagaProtocol := pi.(*dagaauth.Protocol)
	dagaProtocol.LeaderSetup(*req, dagaServer)

	// start  // TODO maybe cleaner to move the start call inside p.waitforresult
	if err = dagaProtocol.Start(); err != nil {
		return nil, fmt.Errorf("failed to start %s protocol: %s", dagaauth.Name, err)
	}
	log.Lvlf3("service started %s protocol, waiting for completion", dagaauth.Name)
	return dagaProtocol, nil
}

// function called to initialize and start a new dagachallengegeneration protocol where current node takes a "Leader" role
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

	// start  // TODO maybe cleaner to move the start call inside p.waitforresult
	if err = challengeGeneration.Start(); err != nil {
		return nil, fmt.Errorf("failed to start %s protocol: %s", dagachallengegeneration.Name, err)
	}
	log.Lvlf3("service started %s protocol, waiting for completion", dagachallengegeneration.Name)
	return challengeGeneration, nil
}

// function called to initialize and start a new dagacontextgeneration protocol where current node takes a "Leader" role
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

	// start  // TODO maybe cleaner to move the start call inside p.waitforresult
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
// TODO if possible share code between protocols (same structure, => new interface and call ChildSetup on it ?)
//  and if like now the setup for children becomes more and more similar to the one for Leader,
//  consider making small modifications to get rid of this NewProtocol, return nil, nil and have everything in protocol if possible
func (s *Service) NewProtocol(tn *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl3("received protocol msg, instantiating new protocol instance of " + tn.ProtocolName())

	switch tn.ProtocolName() {
	case dagachallengegeneration.Name:
		pi, err := dagachallengegeneration.NewProtocol(tn)
		if err != nil {
			return nil, err
		}
		challengeGeneration := pi.(*dagachallengegeneration.Protocol)
		challengeGeneration.ChildSetup(s.ValidatePKClientReq)
		return challengeGeneration, nil
	case dagaauth.Name:
		pi, err := dagaauth.NewProtocol(tn)
		if err != nil {
			return nil, err
		}
		dagaServerProtocol := pi.(*dagaauth.Protocol)
		dagaServerProtocol.ChildSetup(s.validateContext)
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

// saves all data/state. in permanent storage (bbolt db)
// FIXME encrypt, contains Servers secrets
//  or avoid by don't storing secrets and derive them from {nodekey, context infos} and a KDF to be able to rebuild them in SetupState
func (s *Service) save() {
	s.Storage.State.RLock()
	defer s.Storage.State.RUnlock()

	err := s.Save(storageID, s.Storage)
	if err != nil {
		log.Error("Couldn't save service data: ", err)
	}
}

// Tries to load a previously saved state from the permanent storage (bbolt db), if not found setup a new one.
func (s *Service) setupState() error {
	// TODO if state kept (see later, see context evolution and verification comment/TODOs) protect sensitive state with something similar to https://github.com/awnumar/memguard
	if s.Storage == nil {
		msg, err := s.Load(storageID)
		if err != nil {
			return err
		}
		if msg == nil {
			// key does not exists, first time
			// TODO if idea to "recursively" use DAGA to authenticate AND authorize createcontext requests retained,
			//  load "administrative" daga context from somewhere here
			s.Storage = &Storage{
				State: newState(),
			}
			return nil
		} else {
			var ok bool
			s.Storage, ok = msg.(*Storage)
			if !ok {
				return errors.New("tryLoad: data of wrong type")
			}
			return nil
		}
	} else {
		// state is already initialized
		return nil
	}
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

// PopulateServiceState is used only from testing code, it is ~ the testing counterpart of `startServingContext`,
// allow the testing code to setup some state.
func (s *Service) PopulateServiceState(context *dagacothority.Context, dagaServer daga.Server) error {
	if context == nil || context.ServiceID == dagacothority.ServiceID(uuid.Nil) || dagaServer == nil {
		return errors.New("PopulateServiceState: illegal args")
	}
	s.Storage.State.set(context.ServiceID, &ServiceState{
		ID: context.ServiceID,
		ContextStates: map[dagacothority.ContextID]*ContextState{
			context.ContextID: {
				DagaServer: *dagacothority.NetEncodeServer(dagaServer),
				Context:    *context,
			},
		},
	})
	return nil
}

// starts serving (accepting requests related to) `context` using `dagaServer`
func (s *Service) startServingContext(context dagacothority.Context, dagaServer daga.Server) error {

	// TODO here publish to byzcoin etc.. ? (and decide what should be done by who and when..)
	//  but IMO it's to the 3rd party service responsibility to publish (or trigger the publishing of) the context and to chose where)
	//  and if no matter my opinion still want to publish from daga cothority, do it only from Leader
	//  (currently the following function is called at all nodes at the end of context generation protocol)

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

	// save all state to bbolt permanent storage
	s.save()
	return nil
}

// newService receives the context that holds information about the node it's
// running on. Saving and loading can be done using the context. The data will
// be stored in memory for tests and simulations, and on disk for real deployments
func newService(c *onet.Context) (onet.Service, error) {
	s := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
	}
	if err := s.RegisterHandlers(s.Auth, s.PKClient, s.CreateContext, s.traffic); err != nil {
		return nil, errors.New("Couldn't register service's API handlers/messages: " + err.Error())
	}
	if err := s.setupState(); err != nil {
		return nil, err
	}
	return s, nil
}
