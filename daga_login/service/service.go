package service

/*
The service.go defines what to do for each API-call. This part of the service
runs on the node.
*/

import (
	"errors"
	"fmt"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/dedis/student_18_daga/daga_login"
	"github.com/dedis/student_18_daga/daga_login/protocols/DAGAChallengeGeneration"
	"github.com/dedis/student_18_daga/sign/daga"
	"sync"
)

// Used for tests
var templateID onet.ServiceID
var suite = daga.NewSuiteEC()

func init() {
	var err error
	templateID, err = onet.RegisterNewService(daga_login.ServiceName, newService)
	log.ErrFatal(err)
	network.RegisterMessages(storage{}, daga_login.NetContext{})
}

// Service is our template-service // TODO doc + rename (or QUESTION maybe rename only package DAGA.service DAGA.ChallengeGenerationProtocol etc.. what is the best ?)
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
	Context daga_login.NetContext   // current DAGA context and respective roster
	DagaServer daga_login.NetServer // daga server (for context)
	// (TODO/enhancement add facilities to handle multiple contexts at once, with possibly multiple DAGA server identities)
	sync.Mutex
}

// Auth starts the server's protocols (daga 4.3.6)
func (s *Service) Auth(req *daga_login.Auth) (*daga_login.AuthReply, error) {
	// TODO validate req
	// TODO ring
	return nil, fmt.Errorf("unimplemented")
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

// helper to check if we accept the context that was sent part of the Auth request
func (s Service) acceptContext(reqContext daga_login.Context) bool {
	// TODO enhancement instead of supporting a single context add facilities to be part of multiple daga auth. context
	currentContext, err := s.storage.Context.NetDecode()
	if err != nil {
		log.Error("failed to decode stored context: %s", err)
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

// PKClient starts the challenge generation protocols, the server will take the role of Leader
func (s *Service) PKClient(req *daga_login.PKclientCommitments) (*daga_login.PKclientChallenge, error) {
	// verify that submitted request is valid and accepted by our node
	context, err := s.validatePKClientReq(req)
	if err != nil {
		return nil, errors.New("PKClient: " + err.Error())
	}

	// start challenge generation protocol
	if challengeGeneration, err := s.newDAGAChallengeGenerationProtocol(context); err != nil {
		return nil, errors.New("PKClient: " + err.Error())
	} else {
		challenge, err := challengeGeneration.WaitForResult()
		return (*daga_login.PKclientChallenge)(&challenge), err
	}
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
	log.Lvl3("service started DAGAChallengeGeneration protocol, waiting for completion")
	return challengeGeneration, nil
}

// NewProtocol is called upon reception of a Protocol's first message when Onet needs
// to instantiate the protocol. A Service is expected to manually create
// the ProtocolInstance it is using. So this method will be potentially called on all nodes of a Tree (except the root, since it is
// the one starting the protocols) to generate the PI on those nodes.
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
	default:
		log.Panic("not implemented")
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
		// first time or nothing, load from setup files FIXME temp hack
		context, err := daga_login.ReadContext("./context.bin")
		// TODO FIXME facilities to check context validity (are we part of the context, are all generators generators, etc..)
		if err != nil {
			return errors.New("tryLoad: first run, failed to read context from config file: " + err.Error())
		}
		netContext := context.NetEncode()
		s.storage.Context = *netContext

		// build daga server // TODO FIXME QUESTION how to do it when we are no longer hacking... ? (pass setup info to service) + how to allow mutliple servers ?
		indexInContext, _ := context.ServerIndexOf(s.ServerIdentity().Public)
		dagaServer, err := daga.NewServer(suite, indexInContext, s.ServerIdentity().GetPrivate())
		if err != nil {
			return errors.New("tryLoad: first run, failed to setup daga Server from config file: " + err.Error())
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
		return nil, errors.New("Couldn't register messages: " + err.Error())
	}
	if err := s.tryLoad(); err != nil {
		log.Error(err)
		return nil, err
	}
	return s, nil
}
