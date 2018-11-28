package dagacontextgeneration

/*
This file provides a Onet-protocol implementing the context generation protocol described in
Syta - Identity Management Through Privacy Preserving Aut Chapter 4.7.3

The protocol is meant to be launched upon reception of a CreateContext request by the DAGA service using the
`newDAGAContextGenerationProtocol`-method of the service (that will take care of doing things right.)
*/

import (
	"errors"
	"fmt"
	"github.com/dedis/kyber"
	"github.com/dedis/onet/network"
	"github.com/dedis/student_18_daga/dagacothority"
	"github.com/dedis/student_18_daga/sign/daga"
	"github.com/satori/go.uuid"
	"time"

	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
)

// the DAGA crypto suite
var suite = daga.NewSuiteEC()

// QUESTION TODO educated timeout formula that scale with number of nodes etc..
const Timeout = 5 * time.Second

// TODO when something wrong (see below/search dishonest) flag leader as dishonest (how ? new protocol with proofs etc.. )

func init() {
	network.RegisterMessage(Announce{}) // register here first message of protocol s.t. every node know how to handle them (before NewProtocol has a chance to register all the other, since it won't be called if onet doesnt know what do to with them)
	onet.GlobalProtocolRegister(Name, NewProtocol)
}

// Protocol holds the state of the context generation protocol instance.
type Protocol struct {
	*onet.TreeNodeInstance
	result              chan dagacothority.Context                                        // channel that will receive the result of the protocol, only root/leader read/write to it
	context             *ContextFactory                                                   // the context being built (used only by leader)
	indexOf             map[onet.TreeNodeID]int                                           // map treeNodes to their index (used only by leader)
	dagaServer          daga.Server                                                       // to hold the newly created "daga identity" of the node for the new context/round
	originalRequest     *dagacothority.CreateContext                                      // set by leader/service, from API call and then propagated to other instances as part of the announce message, to allow them to decide to proccess request or not
	acceptRequest       func(ctx *dagacothority.CreateContext) error                      // used by child nodes to verify that a request (forwarded by leader) is valid and accepted by the node, set by service at protocol creation time
	startServingContext func(context dagacothority.Context, dagaServer daga.Server) error // used by child nodes to provide result of protocol to the parent service, set by service at protocol creation time
}

type ContextFactory struct {
	ServiceID dagacothority.ServiceID
	daga.MinimumAuthenticationContext
	Signatures [][]byte
}

// General infos: NewProtocol initialises the structure for use in one round, callback passed to onet upon protocol registration
// and used to instantiate protocol instances, on the Leader/root (done by onet.CreateProtocol) and on other nodes upon reception of
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
	for _, handler := range []interface{}{t.HandleAnnounce, t.HandleAnnounceReply,
		t.HandleSign, t.HandleSignReply,
		t.HandleDone} {
		if err := t.RegisterHandler(handler); err != nil {
			return nil, errors.New("couldn't register handler: " + err.Error())
		}
	}
	return t, nil
}

// setup function that needs to be called after protocol creation on Leader/root (and only at that time !)
func (p *Protocol) LeaderSetup(req *dagacothority.CreateContext) {
	if p.result != nil || p.context != nil || p.indexOf != nil || p.dagaServer != nil { // TODO
		log.Panic("protocol setup: LeaderSetup called on an already initialized node.")
	}
	// store original request (to be able to forward it to other nodes)
	if req == nil || req.DagaNodes == nil || req.ServiceID == dagacothority.ServiceID(uuid.Nil) || len(req.Signature) == 0 || len(req.SubscribersKeys) == 0 {
		log.Panic("protocol setup: empty request")
	}
	p.originalRequest = req

	// create context skeleton/factory
	p.context = &ContextFactory{
		ServiceID: req.ServiceID,
		MinimumAuthenticationContext: daga.MinimumAuthenticationContext{
			G: struct {
				X []kyber.Point
				Y []kyber.Point
			}{X: req.SubscribersKeys, Y: make([]kyber.Point, p.Tree().Size())},
			R: make([]kyber.Point, p.Tree().Size()),
			H: make([]kyber.Point, len(req.SubscribersKeys)),
		},
		Signatures: make([][]byte, p.Tree().Size()),
	}

	p.indexOf = make(map[onet.TreeNodeID]int)
}

// setup function that needs to be called after protocol creation on other (non root/Leader) tree nodes
func (p *Protocol) ChildSetup(acceptRequest func(*dagacothority.CreateContext) error,
	startServingContext func(context dagacothority.Context, dagaServer daga.Server) error) {
	if p.result != nil || p.context != nil || p.indexOf != nil || p.dagaServer != nil { // TODO
		log.Panic("protocol setup: ChildSetup called on an already initialized node.")
	}
	p.setAcceptRequest(acceptRequest)
	p.setStartServingContext(startServingContext)
}

// TODO probably remove those "not that useful setters"/avoid to be frowned upon ^^
// setter to let know the protocol instance "what is the request validation strategy"
func (p *Protocol) setAcceptRequest(acceptRequest func(*dagacothority.CreateContext) error) {
	if acceptRequest == nil {
		log.Panic("protocol setup: nil request validator (acceptRequest())")
	}
	p.acceptRequest = acceptRequest
}

// setter to let know the parent service instance "what was the result of the protocol"
func (p *Protocol) setStartServingContext(startServingContext func(context dagacothority.Context, dagaServer daga.Server) error) {
	if startServingContext == nil {
		log.Panic("protocol setup: nil startServingContext()")
	}
	p.startServingContext = startServingContext
}

// Start sends the Announce-message to all children,
func (p *Protocol) Start() (err error) {
	defer func() {
		if err != nil {
			p.Done()
		}
	}()

	// quick check that give hint that every other node is indeed a direct child of root.
	if len(p.Children()) != len(p.context.ServersSecretsCommitments())-1 {
		return errors.New(Name + ": failed to start: tree has invalid shape")
	}
	log.Lvlf3("leader (%s) started %s protocol", p.ServerIdentity(), Name)

	// initialize the channel used to : grab results / synchronize with WaitForResult
	p.result = make(chan dagacothority.Context)

	// create new daga.Server identity for this context (personal choice can decide to reuse one existing Y key...)
	dagaServer, err := daga.NewServer(suite, 0, nil)
	if err != nil {
		return errors.New(Name + ": failed to handle Leader's Announce: " + err.Error())
	}
	// pick new random per-round secret r and its commitment R
	R := daga.GenerateNewRoundSecret(suite, dagaServer) // TODO remember the refactor note in GenerateNewRoundSecret

	// save in state
	p.dagaServer = dagaServer

	// update the context that's being created
	p.context.G.Y[0] = dagaServer.PublicKey()
	p.context.R[0] = R

	// broadcast Announce requesting that all other nodes do the same and send back their (potentially new) public key Y and commitment R.
	var errs []error
	for i, treeNode := range p.Children() {
		assignedIndex := i + 1
		p.indexOf[treeNode.ID] = assignedIndex

		if err := p.SendTo(treeNode, &Announce{
			AssignedIndex:   assignedIndex,
			OriginalRequest: *p.originalRequest,
		}); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) != 0 {
		return fmt.Errorf(Name+": failed to start: broadcast of Announce failed with error(s): %v", errs)
	}
	return nil
}

// Wait for protocol result or timeout, must be called on root instance only (meant to be called by the service, after Start)
func (p *Protocol) WaitForResult() (dagacothority.Context, daga.Server, error) {
	if p.result == nil {
		log.Panicf("%s: WaitForResult called on an uninitialized protocol instance or non root/Leader protocol instance or before Start", Name)
	}
	// wait for protocol result or timeout
	select {
	case finalContext := <-p.result:
		log.Lvlf3("finished %s protocol, resulting context: %v", Name, finalContext)
		return finalContext, p.dagaServer, nil
	case <-time.After(Timeout):
		return dagacothority.Context{}, nil, fmt.Errorf("%s didn't finish in time", Name)
	}
}

// handler that is called on "slaves" upon reception of Leader's Announce message
func (p *Protocol) HandleAnnounce(msg StructAnnounce) (err error) {
	defer func() {
		if err != nil {
			p.Done()
		}
	}()
	log.Lvlf3("%s: Received Leader's Announce", Name)

	// check if the request is accepted by the node before acceding to leader's request
	if err := p.acceptRequest(&msg.OriginalRequest); err != nil {
		return errors.New(Name + ": failed to handle Leader's Announce: " + err.Error())
	} else {
		// store, to verify later that the context built by leader with our participation match the original request
		p.originalRequest = &msg.OriginalRequest
	}

	leaderTreeNode := msg.TreeNode

	// create new daga.Server identity for this context (personal choice can decide to reuse one existing Y key...)
	dagaServer, err := daga.NewServer(suite, msg.AssignedIndex, nil)
	if err != nil {
		return errors.New(Name + ": failed to handle Leader's Announce: " + err.Error())
	}
	// pick new random per-round secret r and its commitment R
	R := daga.GenerateNewRoundSecret(suite, dagaServer) // TODO remember the refactor note in GenerateNewRoundSecret

	// save in own state
	p.dagaServer = dagaServer

	// send back infos to leader
	return p.SendTo(leaderTreeNode, &AnnounceReply{
		Y: dagaServer.PublicKey(),
		R: R,
	})
}

// handler that will be called by framework when Leader node has received an AnnounceReply from all other nodes (its children)
func (p *Protocol) HandleAnnounceReply(msg []StructAnnounceReply) (err error) {
	defer func() {
		if err != nil {
			p.Done()
		}
	}()
	log.Lvlf3("%s: Leader received all Announce replies", Name) // remember that for correct aggregation of messages the tree must have correct shape

	// update context
	for _, announceReply := range msg {
		p.context.G.Y[p.indexOf[announceReply.ID]] = announceReply.Y
		p.context.R[p.indexOf[announceReply.ID]] = announceReply.R
	}

	// create client generators
	for i, _ := range p.context.G.X {
		if p.context.H[i], err = daga.GenerateClientGenerator(suite, i, p.context.R); err != nil {
			return fmt.Errorf("%s: failed to handle AnnounceReply: %s", Name, err.Error())
		}
	}

	// broadcast the now "done" context
	errs := p.Broadcast(&Sign{
		Context: p.context.MinimumAuthenticationContext,
	})
	if len(errs) != 0 {
		return fmt.Errorf("%s: broadcast of Sign failed with error(s): %v", Name, errs)
	}
	return nil
}

// handler that is called on "slaves" upon reception of Leader's Sign message
func (p *Protocol) HandleSign(msg StructSign) (err error) {
	defer func() {
		if err != nil {
			p.Done()
		}
	}()
	log.Lvlf3("%s: Received Leader's Sign", Name)

	// verify that our Y,R is correct in context
	R := suite.Point().Mul(p.dagaServer.RoundSecret(), nil) // TODO remove this nonsense and add a new keypair in daga.Server
	Y := p.dagaServer.PublicKey()
	if !R.Equal(msg.Context.R[p.dagaServer.Index()]) {
		return fmt.Errorf("%s: failed to handle (dishonest)Leader's Sign: wrong node commitment", Name)
	} else if !Y.Equal(msg.Context.G.Y[p.dagaServer.Index()]) {
		return fmt.Errorf("%s: failed to handle (dishonest)Leader's Sign: wrong node public key", Name)
	}

	// TODO FIXME how can the nodes verify that the other keys are not sybil keys of leader ?
	// TODO (and if the case what can go wrong, since can assume we are honest and daga works in anytrust => nothing can go wrong or ?)

	// verify that the generators are correctly computed (do it again)
	for i, leaderGenerator := range msg.Context.H {
		if generator, err := daga.GenerateClientGenerator(suite, i, msg.Context.R); err != nil {
			return fmt.Errorf("%s: failed to handle Leader's Sign: %s", Name, err)
		} else if !leaderGenerator.Equal(generator) {
			return fmt.Errorf("%s: failed to handle (dishonest)Leader's Sign: wrong generator", Name)
		}
	}

	// verify context is actually answering original request (same subscribers)
	if !dagacothority.ContainsSameElems(p.originalRequest.SubscribersKeys, msg.Context.G.X) {
		return fmt.Errorf("%s: failed to handle (dishonest)Leader's Sign: wrong group members in context", Name)
	}

	// sign context // TODO include roster and other metadata in signature
	contextBytes, err := daga.AuthenticationContextToBytes(msg.Context)
	if err != nil {
		return fmt.Errorf("%s: failed to handle Leader's Sign: %s", Name, err)
	}
	signature, err := daga.SchnorrSign(suite, p.dagaServer.PrivateKey(), contextBytes)
	if err != nil {
		return fmt.Errorf("%s: failed to handle Leader's Sign: %s", Name, err)
	}

	// send our signature back to leader
	return p.SendTo(msg.TreeNode, &SignReply{
		Signature: signature,
	})
}

// handler that will be called by framework when Leader node has received a SignReply from all other nodes (its children)
func (p *Protocol) HandleSignReply(msg []StructSignReply) (err error) {
	defer p.Done()
	log.Lvlf3("%s: Leader received all Sign replies", Name)

	contextBytes, err := daga.AuthenticationContextToBytes(p.context)
	if err != nil {
		return fmt.Errorf("%s: failed to handle SignReply: %s", Name, err)
	}

	// verify all the signatures and add them to the context being built
	for _, signReply := range msg {
		nodeIndex := p.indexOf[signReply.ID]
		Y := p.context.G.Y[nodeIndex]
		if err := daga.SchnorrVerify(suite, Y, contextBytes, signReply.Signature); err != nil {
			return fmt.Errorf("%s: failed to handle SignReply: %s", Name, err)
		}
		p.context.Signatures[nodeIndex] = signReply.Signature
	}

	// add own signature
	if signature, err := daga.SchnorrSign(suite, p.dagaServer.PrivateKey(), contextBytes); err != nil {
		return fmt.Errorf("%s: failed to handle SignReply: %s", Name, err)
	} else {
		p.context.Signatures[0] = signature
	}

	// make result available to service
	finalContext, err := dagacothority.NewContext(*p.context, p.Roster(), p.context.ServiceID, p.context.Signatures)
	if err != nil {
		return fmt.Errorf("%s: failed to handle SignReply: %s", Name, err)
	}
	p.result <- *finalContext

	// broadcast the now done context
	errs := p.Broadcast(&Done{
		FinalContext: *finalContext,
	})
	if len(errs) != 0 {
		return fmt.Errorf("%s: broadcast of Done failed with error(s): %v", Name, errs)
	}
	return nil
}

// handler that will be called by framework when node received a Done msg from Leader
func (p *Protocol) HandleDone(msg StructDone) error {
	defer p.Done()
	log.Lvlf3("%s: Received Done", Name)

	// verify signatures // TODO/FIXME use keys from the context at the HandleSign step to prevent leader replacing the keys (if useful, see remark at HandleSign step)
	members := msg.FinalContext.Members()
	if contextBytes, err := daga.AuthenticationContextToBytes(msg.FinalContext); err != nil { // TODO see to include other things (roster, Ids etc..)
		return fmt.Errorf("%s: failed to handle Done: %s", Name, err)
	} else {
		for i, pubKey := range members.Y {
			if err := daga.SchnorrVerify(suite, pubKey, contextBytes, msg.FinalContext.Signatures[i]); err != nil {
				return fmt.Errorf("%s: failed to handle Done: %s", Name, err)
			}
		}
	}

	// make context and matching dagaServer identity available to parent service
	return p.startServingContext(msg.FinalContext, p.dagaServer)
}
