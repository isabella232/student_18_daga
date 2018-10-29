package DAGA

// QUESTION not sure if each protocol deserve its own package but if I put them all in same package (say protocol) will need to change a little the template conventions
// QUESTION : purpose of shutdown, cleanup when protocol done ?, automatically called or manually called ?

/*
The `NewProtocol` method is used to define the protocol and to register
the handlers that will be called if a certain type of message is received.
The handlers will be treated according to their signature.

The protocol-file defines the actions that the protocol needs to do in each
step. The root-node will call the `Start`-method of the protocol. Each
node will only use the `Handle`-methods, and not call `Start` again.

*/

import (
	"errors"
	"fmt"
	"github.com/dedis/onet/network"
	"github.com/dedis/student_18_daga/daga_login"
	"github.com/dedis/student_18_daga/daga_login/protocols"
	"github.com/dedis/student_18_daga/sign/daga"
	"time"

	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
)

var suite = daga.NewSuiteEC()

// TODO educated timeout formula that scale with number of nodes etc..
const Timeout = 10 * time.Second

func init() {
	network.RegisterMessage(ServerMsg{}) // register here first message of protocol s.t. every node know how to handle them (before NewProtocol has a chance to register all the other, since it won't be called if onet doesnt know what do to with them)
	// QUESTION protocol is tied to service => according to documentation I need to call Server.ProtocolRegisterName
	// QUESTION Where ?
	// QUESTION need more info on all of this works and what are the possible scenarios, documentation not clear enough nor up to date
	onet.GlobalProtocolRegister(Name, NewProtocol) // FIXME remove
}

// DAGAChallengeGenerationProtocol holds the state of the challenge generation protocol.
type DAGAProtocol struct {
	*onet.TreeNodeInstance
	result        chan daga.ServerMessage
	dagaServer    daga.Server                         // the daga server of this protocol instance, should be populated from infos taken from Service at protocol creation time (see LeaderSetup and ChildrenSetup)
	request       daga_login.NetAuthenticationMessage // the client's request (set by service using LeaderSetup), used only by leader/first node
	acceptContext func(daga_login.Context) bool       // a function to call to verify that context is accepted by our node (set by service at protocol creation time)
}

// NewProtocol initialises the structure for use in one round (at the root/leader), callback passed to onet upon protocol registration
// and used to instantiate protocol instances, if service.NewProtocol returns nil, nil this one will be called on children too.
func NewProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	t := &DAGAProtocol{
		TreeNodeInstance: n,
	}
	for _, handler := range []interface{}{t.HandleServerMsg, t.HandleFinishedServerMsg} {
		if err := t.RegisterHandler(handler); err != nil {
			return nil, errors.New("couldn't register handler: " + err.Error())
		}
	}
	return t, nil
}

// setup function that needs to be called after protocol creation on Leader/root (and only at that time !)
func (p *DAGAProtocol) LeaderSetup(req daga_login.NetAuthenticationMessage, dagaServer daga.Server) {
	if p.dagaServer != nil || p.result != nil {
		log.Panic("protocol setup: LeaderSetup called on an already initialized node.")
	}
	p.setRequest(req)
	p.setDagaServer(dagaServer)
	p.result = make(chan daga.ServerMessage)
}

// setup function that needs to be called after protocol creation on other tree nodes
func (p *DAGAProtocol) ChildrenSetup(dagaServer daga.Server, acceptContext func(ctx daga_login.Context) bool) {
	if p.dagaServer != nil || p.result != nil {
		log.Panic("protocol setup: ChildrenSetup called on an already initialized node.")
	}
	p.setDagaServer(dagaServer)
	p.setAcceptContext(acceptContext)
}

func (p *DAGAProtocol) setAcceptContext(acceptContext func(ctx daga_login.Context) bool) {
	if acceptContext == nil {
		log.Panic("protocol setup: nil context validator (acceptContext())")
	}
	p.acceptContext = acceptContext
}

// setter to let know the protocol instance "which daga.Server it is"
func (p *DAGAProtocol) setDagaServer(dagaServer daga.Server) {
	if dagaServer == nil { //|| reflect.ValueOf(dagaServer).IsNil() {
		log.Panic("protocol setup: nil daga server")
	}

	p.dagaServer = dagaServer
}

func (p *DAGAProtocol) setRequest(request daga_login.NetAuthenticationMessage) {
	// TODO see what to check here, everything should already be ok...
	p.request = request
}

// Start sends TODO
// Step 1 of daga server's protocol described in Syta - 4.3.6
func (p *DAGAProtocol) Start() error {
	// TODO check tree shape
	log.Lvlf3("leader (%s) started %s", p.ServerIdentity(), Name)

	// leader initialize the server message with the request from the client
	request, context, _ := p.request.NetDecode()
	serverMsg, err := daga.InitializeServerMessage(request)
	if err != nil {
		return fmt.Errorf("%s: %s", Name, err)
	}

	// run "protocol"
	if err := daga.ServerProtocol(suite, serverMsg, p.dagaServer); err != nil {
		return fmt.Errorf("%s: %s", Name, err)
	}

	return p.sendToNextServer(context, &ServerMsg{
		NetServerMessage: *daga_login.NetEncodeServerMessage(context, serverMsg),
	})
}

// Wait for protocol result or timeout, must be called on root instance
func (p *DAGAProtocol) WaitForResult() (daga.ServerMessage, error) {
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

// TODO
func (p *DAGAProtocol) HandleServerMsg(msg StructServerMsg) error {
	log.Lvlf3("%s: Received ServerMsg", Name)

	// decode
	serverMsg, context, err := msg.NetDecode() //NetServerMsg.NetDecode()
	if err != nil {
		return fmt.Errorf("%s: %s", Name, err)
	}

	if !p.acceptContext(context) {
		return fmt.Errorf("%s: context not accepted by node", Name)
	}

	// run "protocol"
	if err := daga.ServerProtocol(suite, serverMsg, p.dagaServer); err != nil {
		return fmt.Errorf("%s: %s", Name, err)
	}

	_, Y := context.Members()
	weAreLastServer := len(serverMsg.Indexes) == len(Y)

	netServerMsg := *daga_login.NetEncodeServerMessage(context, serverMsg)
	if weAreLastServer {
		errs := p.Broadcast(&FinishedServerMsg{
			NetServerMessage: netServerMsg,
		})
		if len(errs) != 0 {
			return fmt.Errorf(Name+": failed to terminate: broadcast of FinishedServerMsg failed with error(s): %v", errs)
		}
		return nil
	} else {
		return p.sendToNextServer(context, &ServerMsg{
			NetServerMessage: netServerMsg,
		})
	}
}

func (p *DAGAProtocol) HandleFinishedServerMsg(msg StructFinishedServerMsg) error {

	log.Lvlf3("%s: Received FinishedServerMsg", Name)

	weAreLeader := p.acceptContext == nil // TODO FIXME what could be a better way ??.. don't like using things for multiple non obvious purposes => maybe decide that leader is at root of tree (and bye bye the potential "ring-tree")

	serverMsg, context, err := msg.NetDecode()
	if err != nil {
		return fmt.Errorf("%s: %s", Name, err)
	}

	// verify and extract tag
	_, err = daga.GetFinalLinkageTag(suite, context, *serverMsg)
	if err != nil {
		return fmt.Errorf("%s: cannot verify server message: %s", Name, err)
	}

	if !weAreLeader {
		// TODO do something.. don't know ..keep somewhere tag for later usage in login service
	} else {
		// make resulting message (and hence final linkage tag available to service => send back to client
		p.result <- *serverMsg // TODO maybe send netServerMsg instead => save one encoding to the service
	}

	return nil
}

func (p *DAGAProtocol) sendToNextServer(context daga_login.Context, msg interface{}) error {
	// figure out the node of the next-server in "ring"
	_, Y := context.Members()
	nextServerTreeNode := protocols.NextNode(p.dagaServer.Index(), Y, p.Tree().List())
	if nextServerTreeNode == nil {
		return fmt.Errorf("failed to find next node")
	}

	// TODO FIXME if possible and if make sense would like to check if same serverIdentity that the one in Context.Roster...
	// TODO Or should we always trust Tree etc.. ? and if that doesnt make sense maybe the Roster in Context in superfluous and only complexify the code
	// (currently only used to communicate a roster from client to service for service to build the tree)
	// anyway if cannot do more clever things here, then the whole function is pointless, can use sendto(nextnode(), etc..) at the calling site

	// send to next server in line
	return p.SendTo(nextServerTreeNode, msg)
}
