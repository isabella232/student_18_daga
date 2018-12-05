package dagaauth

// QUESTION not sure if each protocol deserve its own package + what would be a sound organization
// QUESTION (if I put them all in same package (say protocol or DAGA) will need to change a little the template conventions
// IMO better: DAGA.PKCLientChallengeGenerationProtocol, DAGA.ServerProtocol, DAGA.Service etc..
// FIXME rename everything to follow conventions when decided

/*
This file provides a Onet-protocol implementing the "DAGA Server's protocol" described in
Syta - Identity Management Through Privacy Preserving Aut Chapter 4.3.6

The protocol is meant to be launched upon reception of an Auth request by the DAGA service using the
`newDAGAServerProtocol`-method of the service (that will take care of doing things right.)
*/

import (
	"errors"
	"fmt"
	"github.com/dedis/onet/network"
	"github.com/dedis/student_18_daga/dagacothority"
	"github.com/dedis/student_18_daga/dagacothority/protocols"
	"github.com/dedis/student_18_daga/sign/daga"
	"time"

	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
)

var suite = daga.NewSuiteEC()

// Timeout represents the max duration/amount of time to wait for result in WaitForResult
// TODO educated timeout formula that scale with number of nodes etc..
const Timeout = 10 * time.Second

func init() {
	network.RegisterMessage(ServerMsg{}) // register here first message of protocol s.t. every node know how to handle them (before NewProtocol has a chance to register all the other, since it won't be called if onet doesnt know what do to with them)
	// QUESTION protocol is tied to service => according to documentation I need to call Server.ProtocolRegisterName
	// QUESTION Where ?
	onet.GlobalProtocolRegister(Name, NewProtocol) // FIXME remove or ?? see question above
}

// Protocol holds the state of the protocol instance.
type Protocol struct {
	*onet.TreeNodeInstance
	result chan daga.ServerMessage // channel that will receive the result of the protocol, only root/leader read/write to it  // TODO since nobody likes channel maybe instead of this, call service provided callback (i.e. move waitForResult in service, have leader call it when protocol done => then need another way to provide timeout

	dagaServer    daga.Server                                      // the daga server of this protocol instance, should be populated from infos taken from Service at protocol creation time (see LeaderSetup and ChildSetup)
	request       dagacothority.Auth                               // the client's request (set by service using LeaderSetup)
	acceptContext func(dagacothority.Context) (daga.Server, error) // a function to call to verify that context is accepted by our node (set by service at protocol creation time)
}

// NewProtocol initialises the structure for use in one round, callback passed to onet upon protocol registration
// and used to instantiate protocol instances, on the Leader/root done by onet.CreateProtocol and on other nodes upon reception of
// first protocol message, by the serviceManager that will call service.NewProtocol.
// if service.NewProtocol returns nil, nil this one will be called on children too.
//
// Relevant for this protocol implementation: it is expected that the service DO implement the service.NewProtocol (don't returns nil, nil),
// to manually call this method before calling the ChildSetup method to provide children-node specific state.
// (similarly for the leader-node, it is expected that the service call LeaderSetup)
func NewProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	t := &Protocol{
		TreeNodeInstance: n,
	}
	for _, handler := range []interface{}{t.handleServerMsg, t.handleFinishedServerMsg} {
		if err := t.RegisterHandler(handler); err != nil {
			return nil, errors.New("couldn't register handler: " + err.Error())
		}
	}
	return t, nil
}

// LeaderSetup is a setup function that needs to be called after protocol creation on Leader/root (and only at that time !)
func (p *Protocol) LeaderSetup(req dagacothority.Auth, dagaServer daga.Server) {
	if p.dagaServer != nil || p.result != nil || p.acceptContext != nil {
		log.Panic("protocol setup: LeaderSetup called on an already initialized node.")
	}
	p.setRequest(req)
	p.setDagaServer(dagaServer)
}

// ChildSetup is a setup function that needs to be called after protocol creation on other (non root/Leader) tree nodes
func (p *Protocol) ChildSetup(acceptContext func(ctx dagacothority.Context) (daga.Server, error)) {
	if p.dagaServer != nil || p.result != nil || p.acceptContext != nil {
		log.Panic("protocol setup: ChildSetup called on an already initialized node.")
	}
	p.setAcceptContext(acceptContext)
}

// setter to let know the protocol instance "what is the daga Context validation strategy"
func (p *Protocol) setAcceptContext(acceptContext func(ctx dagacothority.Context) (daga.Server, error)) {
	if acceptContext == nil {
		log.Panic("protocol setup: nil context validator (acceptContext())")
	}
	p.acceptContext = acceptContext
}

// setter to let know the protocol instance "which daga.Server it is"
func (p *Protocol) setDagaServer(dagaServer daga.Server) {
	if dagaServer == nil {
		log.Panic("protocol setup: nil daga server")
	}
	p.dagaServer = dagaServer
}

// setter used to provide the client request to the root protocol instance
func (p *Protocol) setRequest(request dagacothority.Auth) {
	p.request = request
}

// Start initialize the daga.ServerMessage, run the "daga.ServerProtocol" on it and forward it to the next node
//
// Step 1-4 of of daga server's protocol described in Syta - 4.3.6
func (p *Protocol) Start() (err error) {
	defer func() {
		if err != nil {
			p.Done()
		}
	}()

	// TODO check legal tree shape
	log.Lvlf3("leader (%s) started %s", p.ServerIdentity(), Name)

	// initialize the channel used to grab results / synchronize with WaitForResult
	p.result = make(chan daga.ServerMessage)

	// leader initialize the server message with the request from the client
	request, context := p.request.NetDecode()
	serverMsg, err := daga.InitializeServerMessage(request)
	if err != nil {
		return fmt.Errorf("%s: %s", Name, err)
	}

	// run "protocol"
	if err := daga.ServerProtocol(suite, serverMsg, p.dagaServer); err != nil {
		return fmt.Errorf("%s: %s", Name, err)
	}

	return p.sendToNextServer(&ServerMsg{*dagacothority.NetEncodeServerMessage(context, serverMsg)})
}

// WaitForResult waits for protocol result (and return it) or timeout, must be called on root instance only (meant to be called by the service, after Start)
func (p *Protocol) WaitForResult() (daga.ServerMessage, error) {
	if p.result == nil {
		log.Panic("WaitForResult called on an uninitialized protocol instance or non root/Leader protocol instance")
	}

	// wait for protocol result or timeout
	select {
	case serverMsg := <-p.result:
		log.Lvlf3("finished %s, resulting message: %v", Name, serverMsg)
		return serverMsg, nil
	case <-time.After(Timeout):
		return daga.ServerMessage{}, errors.New(Name + " didn't finish in time")
	}
}

// Handler that is called upon reception of the daga.ServerMessage from previous node.
// will check that the context of the request is accepted by current node before
// running the "daga.ServerProtocol" on it and either forwarding it to next node or broadcasting it to all nodes
// if current node is last node
//
// Step 1-4 of of daga server's protocol described in Syta - 4.3.6
func (p *Protocol) handleServerMsg(msg StructServerMsg) (err error) {
	defer func() {
		if err != nil {
			p.Done()
		}
	}()
	log.Lvlf3("%s: Received ServerMsg", Name)

	// decode
	serverMsg, context := msg.NetDecode()
	if err != nil {
		return fmt.Errorf("%s: %s", Name, err)
	}

	// check if context accepted by our node  // FIXME validate entire request like was done for other protocols
	if dagaServer, err := p.acceptContext(context); err != nil {
		return fmt.Errorf("%s: context not accepted by node: %s", Name, err)
	} else {
		p.setDagaServer(dagaServer)
		p.request.Context = context
		//p.setRequest(msg.NetServerMessage.Request)  // TODO maybe for consistency
	}

	// run "protocol"
	if err := daga.ServerProtocol(suite, serverMsg, p.dagaServer); err != nil {
		return fmt.Errorf("%s: %s", Name, err)
	}

	// forward to next node or broadcast to everyone if we are the last one
	members := context.Members()
	weAreLastServer := len(serverMsg.Indexes) == len(members.Y)

	netServerMsg := *dagacothority.NetEncodeServerMessage(context, serverMsg)
	if weAreLastServer {
		// broadcast to everyone (including us)
		msg := FinishedServerMsg{netServerMsg}
		errs := p.Broadcast(&msg)
		if len(errs) != 0 {
			return fmt.Errorf(Name+": failed to terminate: broadcast of FinishedServerMsg failed with error(s): %v", errs)
		}
		return p.SendTo(p.TreeNode(), &msg) // send to self
	} else {
		return p.sendToNextServer(&ServerMsg{netServerMsg})
	}
}

func (p *Protocol) handleFinishedServerMsg(msg StructFinishedServerMsg) error {
	defer p.Done()
	log.Lvlf3("%s: Received FinishedServerMsg", Name)

	weAreLeader := p.acceptContext == nil // TODO FIXME what could be a better way ??.. don't like using things for multiple non obvious purposes => maybe decide that leader is at root of tree (and bye bye the potential "ring-tree")

	serverMsg, context := msg.NetDecode()

	// verify and extract tag
	_, err := daga.GetFinalLinkageTag(suite, context, *serverMsg)
	if err != nil {
		return fmt.Errorf("%s: cannot verify server message: %s", Name, err)
	}

	if !weAreLeader {
		// TODO can do something.. don't know now..keep somewhere tag for later usage in login service
		//  or to keep stats in context etc..and offer a new endpoint in service
		//  because it is a "feature" of daga, can revoke context or auth from user based on some policies
	} else {
		// make resulting message (and hence final linkage tag available to service => send back to client
		p.result <- *serverMsg // TODO maybe send netServerMsg instead => save one encoding to the service
	}
	return nil
}

// TODO see remark in protocols/utils, would be nice to share more code between daga protocols
func (p *Protocol) sendToNextServer(msg interface{}) error {
	// figure out the node of the next-server in "ring"
	// figure out the node of the next-server in "ring"

	// here we pass the public keys of nodes in roster instead of the ones from auth. context to simplify the
	// "ring communication", now the "ring order" is based on the indices of the nodes in context's roster instead of in context
	// like described in DAGA paper (nothing changed fundamentally).
	// this is because nodes can (and probably have) multiple daga server identities (one per context),
	// if we prefer keeping the indices in context for the "ring order",
	// we would need ways to map conodes/treenodes to their daga keys in order to select the next node
	// (see old comments in https://github.com/dedis/student_18_daga/blob/7d32acf216cbdea230d91db6eee633061af58caf/daga_login/protocols/DAGAChallengeGeneration/protocol.go#L411-L417)
	ownIndex, _ := dagacothority.IndexOf(p.request.Context.Roster.Publics(), p.Public())
	if nextServerTreeNode, err := protocols.NextNode(ownIndex, p.request.Context.Roster.Publics(), p.Tree().List()); err != nil {
		return fmt.Errorf("sendToNextServer: %s", err)
	} else {
		// send to next server in ring
		return p.SendTo(nextServerTreeNode, msg)
	}
}
