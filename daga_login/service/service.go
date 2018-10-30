package service

/*

// TODO: implements DAGA, Deniable Anonymous Group Authentication Protocol

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
	"github.com/dedis/student_18_daga/sign/daga"
	"sync"
)

// Used for tests
var templateID onet.ServiceID

// DAGA crypto suite
var suite = daga.NewSuiteEC()

func init() {
	var err error
	templateID, err = onet.RegisterNewService(daga_login.ServiceName, newService)
	log.ErrFatal(err)
	network.RegisterMessages(storage{}, daga_login.NetContext{}, daga_login.NetServer{})
}

// Service is our DAGA-service
// TODO doc + rename ?? (or QUESTION maybe rename only package DAGA.service DAGA.ChallengeGenerationProtocol DAGA.ServersProtocol etc.. or keep template organization what is the best ?)
type Service struct {
	// We need to embed the ServiceProcessor, so that incoming messages
	// are correctly handled.
	*onet.ServiceProcessor
	storage *storage
}

// storageID reflects the data we're storing - we could store more
// than one structure.
var storageID = []byte("main")

// storage is used to save our data.
// always access storage through the helpers/getters !
type storage struct {
	Context    daga_login.NetContext // current DAGA context and respective roster
	DagaServer daga_login.NetServer  // daga server identity of our node (part of context)
	// (TODO/enhancement add facilities to handle multiple contexts at once, with possibly multiple DAGA server identities)
	sync.Mutex
}

// helper to quickly validate Auth requests before proceeding further
func (s Service) validateAuthReq(req *daga_login.Auth) (daga_login.Context, error) {
	if req == nil || len(req.SCommits) == 0 || req.T0 == nil {
		return daga_login.Context{}, errors.New("validateAuthReq: nil or empty request")
	}
	// TODO validate proof
	// FIXME check commitments and challenge same as at proof construction time..etc..see github issue) => probably better in the corresponding daga function
	return s.validateContext(req.Context)
}

// API endpoint Auth,
// starts the server's protocols (daga 4.3.6)
// QUESTION FIXME decide what is returned to client, tag only or full final servermsg ? => if tag only malicious server can identify client..
func (s *Service) Auth(req *daga_login.Auth) (*daga_login.AuthReply, error) {
	// verify that submitted request is valid and accepted by our node
	context, err := s.validateAuthReq(req)
	if err != nil {
		return nil, errors.New("Auth: " + err.Error())
	}

	// start daga server's protocol
	if dagaProtocol, err := s.newDAGAServerProtocol(daga_login.NetAuthenticationMessage(*req)); err != nil {
		return nil, errors.New("Auth: " + err.Error())
	} else {
		serverMsg, err := dagaProtocol.WaitForResult()
		netServerMsg := daga_login.NetEncodeServerMessage(context, &serverMsg)
		return (*daga_login.AuthReply)(netServerMsg), err
	}
}

// helper that check if received context is valid, (fully populated, accepted, etc..)
// returns context, nil if ok to proceed with context, or empty, err otherwise
func (s Service) validateContext(netReqContext daga_login.NetContext) (daga_login.Context, error) {
	// TODO complete if other ideas...
	reqContext, err := netReqContext.NetDecode()
	if err != nil {
		return daga_login.Context{}, fmt.Errorf("validateContext: failed to decode the context that was sent with the request: %s", err)
	}

	if len(reqContext.Roster.List) == 0 {
		return daga_login.Context{}, errors.New("validateContext: sent context contains empty roster")
	}

	if s.acceptContext(reqContext) {
		return reqContext, nil
	} else {
		return daga_login.Context{}, errors.New("validateContext: auth. context part of the request is not accepted by this server")
	}
}

// helper to check if we accept the context that was sent part of the Auth/PKClient request
func (s Service) acceptContext(reqContext daga_login.Context) bool {
	// TODO enhancement instead of supporting a single context add facilities to be part of multiple daga auth. context
	currentContext, err := s.storage.Context.NetDecode()
	if err != nil {
		log.Errorf("failed to decode stored context: %s", err)
		return false
	}
	return currentContext.Equals(reqContext)
}

// helper to validate PKClient requests before proceeding further
func (s Service) validatePKClientReq(req *daga_login.PKclientCommitments) (daga_login.Context, error) {
	if req == nil || len(req.Data) == 0 {
		return daga_login.Context{}, errors.New("validatePKClientReq: nil request or empty commitments")
	}
	return s.validateContext(req.Context)
}

// API endpoint PKClient, upon reception of a valid request,
// starts the challenge generation protocols, the current server/node will take the role of Leader
func (s *Service) PKClient(req *daga_login.PKclientCommitments) (*daga_login.PKclientChallenge, error) {
	// verify that submitted request is valid and accepted by our node
	context, err := s.validatePKClientReq(req)
	if err != nil {
		return nil, errors.New("PKClient: " + err.Error())
	}

	// TODO do something with the commitments, see issue in github

	// start challenge generation protocol
	if challengeGeneration, err := s.newDAGAChallengeGenerationProtocol(context); err != nil {
		return nil, errors.New("PKClient: " + err.Error())
	} else {
		challenge, err := challengeGeneration.WaitForResult()
		return (*daga_login.PKclientChallenge)(&challenge), err
	}
}

// function called to initialize and start a new DAGA (Server's) protocol where current node takes a "Leader" role
func (s *Service) newDAGAServerProtocol(req daga_login.NetAuthenticationMessage) (*DAGA.DAGAProtocol, error) {
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
	dagaProtocol := pi.(*DAGA.DAGAProtocol)
	dagaServer, err := s.dagaServer()
	if err != nil {
		return nil, errors.New("failed to retrieve daga server from service state: " + err.Error())
	}
	dagaProtocol.LeaderSetup(req, dagaServer)

	// start
	if err = dagaProtocol.Start(); err != nil {
		return nil, fmt.Errorf("failed to start %s protocol: %s", DAGA.Name, err)
	}
	log.Lvlf3("service started %s protocol, waiting for completion", DAGA.Name)
	return dagaProtocol, nil
}

// function called to initialize and start a new DAGAChallengeGeneration protocol where current node takes a Leader role
func (s *Service) newDAGAChallengeGenerationProtocol(reqContext daga_login.Context) (*DAGAChallengeGeneration.DAGAChallengeGenerationProtocol, error) {
	// TODO/FIXME see if always ok to use user provided roster... (we already check auth. context)
	// build tree with leader as root
	roster := reqContext.Roster
	// pay attention to the fact that for the protocol to work the tree needs to be correctly shaped !!
	// protocol assumes that all other nodes are direct children of leader (use aggregation before calling some handlers)
	tree := roster.GenerateNaryTreeWithRoot(len(roster.List)-1, s.ServerIdentity())

	// create and setup protocol instance
	pi, err := s.CreateProtocol(DAGAChallengeGeneration.Name, tree)
	if err != nil {
		return nil, errors.New("failed to create " + DAGAChallengeGeneration.Name + " protocol: " + err.Error())
	}
	challengeGeneration := pi.(*DAGAChallengeGeneration.DAGAChallengeGenerationProtocol)
	dagaServer, err := s.dagaServer()
	if err != nil {
		return nil, errors.New("failed to retrieve daga server from service state: " + err.Error())
	}
	challengeGeneration.LeaderSetup(reqContext, dagaServer)

	// start
	if err = challengeGeneration.Start(); err != nil {
		return nil, fmt.Errorf("failed to start %s protocol: %s", DAGAChallengeGeneration.Name, err)
	}
	log.Lvlf3("service started %s protocol, waiting for completion", DAGAChallengeGeneration.Name)
	return challengeGeneration, nil
}

// NewProtocol is called upon reception of a Protocol's first message when Onet needs
// to instantiate the protocol. A Service is expected to manually create
// the ProtocolInstance it is using. So this method will be potentially called on all nodes of a Tree (except the root, since it is
// the one starting the protocols) to generate the PI on those other nodes.
// if it returns nil, nil then the default NewProtocol is called (the one defined in protocol)
// FIXME outdated documentation in template
func (s *Service) NewProtocol(tn *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl3("received protocol msg, instantiating new protocol instance of " + tn.ProtocolName())
	switch tn.ProtocolName() {
	case DAGAChallengeGeneration.Name:
		pi, err := DAGAChallengeGeneration.NewProtocol(tn)
		if err != nil {
			return nil, err
		}
		challengeGeneration := pi.(*DAGAChallengeGeneration.DAGAChallengeGenerationProtocol)
		dagaServer, err := s.dagaServer()
		if err != nil {
			log.Panic("failed to retrieve daga server from service state: " + err.Error())
		}
		challengeGeneration.ChildrenSetup(dagaServer)
		return challengeGeneration, nil
	case DAGA.Name:
		pi, err := DAGA.NewProtocol(tn)
		if err != nil {
			return nil, err
		}
		dagaServerProtocol := pi.(*DAGA.DAGAProtocol)
		dagaServer, err := s.dagaServer()
		if err != nil {
			log.Panic("failed to retrieve daga server from service state: " + err.Error())
		}
		dagaServerProtocol.ChildrenSetup(dagaServer, s.acceptContext)
		return dagaServerProtocol, nil
	default:
		log.Panic("protocol not implemented/known")
	}
	return nil, errors.New("should not be reached")
}

// saves all data.
func (s *Service) save() {
	s.storage.Lock()
	defer s.storage.Unlock()
	err := s.Save(storageID, s.storage)
	if err != nil {
		log.Error("Couldn't save data:", err)
	}
}

// Tries to load the configuration and updates the data in the service
// if it finds a valid config-file
func (s *Service) tryLoad() error {
	s.storage = &storage{}
	msg, err := s.Load(storageID)
	if err != nil {
		return err
	}
	if msg == nil {
		// first time or nothing, load from setup files
		// FIXME temp hack while lacking a proper boot method
		// FIXME QUESTION how to do it when we are no longer hacking... ? (pass setup info to service)

		context, err := daga_login.ReadContext("./context.bin")
		// TODO FIXME facilities to check context validity (are we part of the context, are all generators generators, etc..)
		if err != nil {
			return errors.New("tryLoad: first run, failed to read context from config file: " + err.Error())
		}
		netContext := context.NetEncode()
		s.storage.Context = *netContext

		// retrieve daga server
		indexInContext, _ := context.ServerIndexOf(s.ServerIdentity().Public)
		dagaServer, err := daga_login.ReadServer(fmt.Sprintf("./server%d.bin", indexInContext))
		if err != nil {
			return errors.New("tryLoad: first run, failed to load daga Server from config file: " + err.Error())
		}
		s.storage.DagaServer = *daga_login.NetEncodeServer(dagaServer)
		return nil
	} else {
		var ok bool
		s.storage, ok = msg.(*storage)
		if !ok {
			return errors.New("tryLoad: data of wrong type")
		}
		return nil
	}
}

// returns the daga server struct of this daga service instance, (fetched from storage)
func (s *Service) dagaServer() (daga.Server, error) {
	s.storage.Lock()
	defer s.storage.Unlock()
	if server, err := s.storage.DagaServer.NetDecode(); err != nil {
		return nil, err
	} else {
		return server, nil
	}
}

// newService receives the context that holds information about the node it's
// running on. Saving and loading can be done using the context. The data will
// be stored in memory for tests and simulations, and on disk for real deployments.
func newService(c *onet.Context) (onet.Service, error) {
	s := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
	}
	if err := s.RegisterHandlers(s.Auth, s.PKClient); err != nil {
		return nil, errors.New("Couldn't register service's API handlers/messages: " + err.Error())
	}
	if err := s.tryLoad(); err != nil {
		log.Error(err)
		return nil, err
	}
	return s, nil
}
