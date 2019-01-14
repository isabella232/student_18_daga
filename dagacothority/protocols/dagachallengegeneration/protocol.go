package dagachallengegeneration

// QUESTION not sure if each protocol deserve its own package but if I put them all in same package (say protocol)
//  will need to change a little the template conventions.
// TODO DRY/share code/interface with other protocols if possible (waitresult, leadersetup, etc.. )
//  => maybe create new interface etc..=> can simplify service.go

//
//This file provides a Onet-protocol implementing the challenge generation protocol described in
//Syta - Identity Management Through Privacy Preserving Aut Chapter 4.7.4
//
//The protocol is meant to be launched upon reception of a PKClient request by the DAGA service using the
//`newDAGAChallengeGenerationProtocol`-method of the service (that will take care of doing things right.)


import (
	"errors"
	"fmt"
	"github.com/dedis/kyber"
	"github.com/dedis/onet/network"
	"github.com/dedis/student_18_daga/dagacothority"
	"github.com/dedis/student_18_daga/dagacothority/protocols"
	"github.com/dedis/student_18_daga/sign/daga"
	"time"

	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
)

// the DAGA crypto suite
var suite = daga.NewSuiteEC()

// Timeout represents the max duration/amount of time to wait for result in WaitForResult
// TODO educated timeout formula that scale with number of nodes etc..
const Timeout = 2500 * time.Second

func init() {
	// register here first message of protocol s.t. every node know how to handle them
	// (before NewProtocol has a chance to register all the other, since it won't be called if onet doesnt know what do to with them)
	network.RegisterMessage(Announce{})
	// QUESTION my protocol is tied to service => according to documentation (up to date ??) I need to call Server.ProtocolRegisterName
	// QUESTION Where/Why ?
	// QUESTION need more info on how all of this works and what are the possible scenarios, documentation not clear enough nor up to date
	onet.GlobalProtocolRegister(Name, NewProtocol) // FIXME remove ?
}

// Protocol holds the state of the challenge generation protocol instance.
type Protocol struct {
	*onet.TreeNodeInstance
	result      chan daga.Challenge        // channel that will receive the result of the protocol, only root/leader read/write to it, used to "sync" with waitForResult
	commitments []daga.ChallengeCommitment // on the leader/root: to store every commitments (to random challenge) at correct index (in auth. context), on the children to store leaderCommitment at 0
	openings    []kyber.Scalar             // on the leader/root: to store every opening at correct index (in auth. context), on the children store own opening at 0

	dagaServer daga.Server // the daga server of this protocol instance, should be populated from infos taken from Service at protocol creation time (see LeaderSetup and ChildSetup)

	// FIXME store original PKclientCommitments request instead (now I don't have to decode anymore => doesnt make sense to separate the fields)
	context             dagacothority.Context                                         // the context of the client request (set by leader when received from API call and then propagated to other instances as part of the announce message)
	pKClientCommitments []kyber.Point                                                 // the commitments of the PKClient PK that were sent by client to request our honest distributed challenge
	acceptRequest       func(*dagacothority.PKclientCommitments) (daga.Server, error) // a function to call to verify that request is accepted by our node (set by service at protocol creation time) and valid
}

// NewProtocol initialises the structure for use in one round, callback passed to onet upon protocol registration
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
	for _, handler := range []interface{}{t.handleAnnounce, t.handleAnnounceReply,
		t.handleOpen, t.handleOpenReply,
		t.handleFinalize} {
		if err := t.RegisterHandler(handler); err != nil {
			return nil, errors.New("couldn't register handler: " + err.Error())
		}
	}
	return t, nil
}

// LeaderSetup is a setup function that needs to be called after protocol creation on Leader/root (and only at that time !)
func (p *Protocol) LeaderSetup(req dagacothority.PKclientCommitments, dagaServer daga.Server) {
	// TODO consider removing the dagaServer parameter and accept a request validator that returns dagaserver (like in ChildSetup)
	// TODO (+): less differences between leader and child (-): redundant checks for leader
	if p.commitments != nil || p.openings != nil || p.dagaServer != nil || p.result != nil || p.acceptRequest != nil {
		log.Panic("protocol setup: LeaderSetup called on an already initialized node.")
	}
	if len(req.Context.R) == 0 || len(req.Context.H) == 0 || req.Context.Roster == nil { // TODO later maybe remove for "optimization", already checked by service + see remarks above
		log.Panic("protocol setup: empty request")
	}
	p.context = req.Context
	if len(req.Commitments) != len(p.context.ClientsGenerators())*3 { // TODO later maybe remove for "optimization", already checked by service
		log.Panic("protocol setup: wrong commitments length")
	}
	p.pKClientCommitments = req.Commitments
	p.setDagaServer(dagaServer)
	p.commitments = make([]daga.ChallengeCommitment, len(p.Tree().List()))
	p.openings = make([]kyber.Scalar, len(p.Tree().List()))
}

// ChildSetup is a setup function that needs to be called after protocol creation on other (non root/Leader) tree nodes
func (p *Protocol) ChildSetup(acceptRequest func(*dagacothority.PKclientCommitments) (daga.Server, error)) {
	if p.commitments != nil || p.openings != nil || p.dagaServer != nil || p.result != nil || p.acceptRequest != nil {
		log.Panic("protocol setup: ChildSetup called on an already initialized node.")
	}
	p.setAcceptRequest(acceptRequest)
	p.commitments = make([]daga.ChallengeCommitment, 1)
	p.openings = make([]kyber.Scalar, 1)
}

// TODO see if I keep those setters (if yes maybe add again the one I removed..) or if it is way too overkill and stupid
// setter to let know the protocol instance "what is the request validation strategy"
func (p *Protocol) setAcceptRequest(acceptRequest func(*dagacothority.PKclientCommitments) (daga.Server, error)) {
	if acceptRequest == nil {
		log.Panic("protocol setup: nil request validator (acceptRequest())")
	}
	p.acceptRequest = acceptRequest
}

// setter to let know the protocol instance "which daga.Server it is"
func (p *Protocol) setDagaServer(dagaServer daga.Server) {
	if dagaServer == nil || dagaServer.PrivateKey() == nil { //|| reflect.ValueOf(dagaServer).IsNil() {
		log.Panic("protocol setup: nil daga server")
	}
	p.dagaServer = dagaServer
}

// method called to update state of the protocol (add opening) (sanity checks)
func (p *Protocol) saveOpening(index int, opening kyber.Scalar) {
	if index >= len(p.openings) {
		log.Panicf("index (%d) out of bound while setting openings in state, len(p.openings) = %d", index, len(p.openings))
	}
	if p.openings[index] != nil {
		log.Panicf("already one opening at p.openings[%d]", index)
	}
	if opening == nil {
		log.Panic("nil opening, not storing")
	}
	p.openings[index] = opening
}

// method called to retrieve opening from protocol state (sanity checks)
func (p *Protocol) opening(index int) kyber.Scalar {
	if index >= len(p.openings) {
		log.Panicf("index (%d) out of bound while getting openings from state, len(p.openings) = %d", index, len(p.openings))
	}
	if p.openings[index] == nil {
		log.Panicf("nil at p.openings[%d]", index)
	}
	return p.openings[index]
}

// method called to update state of the protocol (add commitment) (doesn't check commitment signature, call only with commitments whose signature is verified !)
func (p *Protocol) saveCommitment(index int, commitment daga.ChallengeCommitment) {
	if index >= len(p.commitments) {
		log.Panicf("index (%d) out of bound while setting commitment in state, len(p.commitment) = %d, you probably forgot to call ChildSetup", index, len(p.commitments))
	}
	if p.commitments[index].Commit != nil {
		log.Panicf("already one commitment at p.commitment[%d]", index)
	}
	if commitment.Commit == nil {
		log.Panic("nil commitment, not storing")
	}
	p.commitments[index] = commitment
}

// method called to retrieve commitment from protocol state (sanity checks)
func (p *Protocol) commitment(index int) daga.ChallengeCommitment {
	if index >= len(p.commitments) {
		log.Panicf("index (%d) out of bound while getting commitment from state, len(p.commitments) = %d", index, len(p.commitments))
	}
	if p.commitments[index].Commit == nil {
		log.Panicf("nil at p.commitments[%d]", index)
	}
	return p.commitments[index]
}

// Start sends the Announce-message to all children,
// Step 1 of daga challenge generation protocol described in Syta - 4.7.4
func (p *Protocol) Start() (err error) {
	defer func() {
		if err != nil {
			p.Done()
		}
	}()

	// quick check that give hint that every other node is indeed a direct child of root.
	if len(p.Children()) != len(p.context.Members().Y)-1 {
		return errors.New(Name + ": failed to start: tree has invalid shape")
	}
	log.Lvlf3("leader (%s) started %s protocol", p.ServerIdentity(), Name)

	// initialize the channel used to : grab results / synchronize with WaitForResult
	p.result = make(chan daga.Challenge)

	// create leader challenge, signed commitment and opening
	leaderChallengeCommit, leaderOpening, err := daga.NewChallengeCommitment(suite, p.dagaServer)
	if err != nil {
		return errors.New(Name + ": failed to start: " + err.Error())
	}
	// save commitment and opening in state
	p.saveOpening(p.dagaServer.Index(), leaderOpening)
	p.saveCommitment(p.dagaServer.Index(), *leaderChallengeCommit)

	// broadcast Announce requesting that all other nodes do the same and send back their signed commitments.
	// QUESTION do work in new goroutine (here don't see the point but maybe an optimization)
	//  and send in parallel (that's another thing..) as was done in skipchain ?
	// TODO add a "BroadcastInParallel" method in onet
	errs := p.Broadcast(&Announce{
		LeaderCommit:         *leaderChallengeCommit,
		LeaderIndexInContext: p.dagaServer.Index(),
		OriginalRequest: dagacothority.PKclientCommitments{
			Commitments: p.pKClientCommitments,
			Context:     p.context,
		},
	})
	if len(errs) != 0 {
		return fmt.Errorf(Name+": failed to start: broadcast of Announce failed with error(s): %v", errs)
	}
	return nil
}

// WaitForResult waits for protocol result (and return it) or timeout, must be called on root instance only (meant to be called by the service, after Start)
func (p *Protocol) WaitForResult() (daga.Challenge, error) {
	if p.result == nil {
		log.Panicf("%s: WaitForResult called on an uninitialized protocol instance or non root/Leader protocol instance or before Start", Name)
	}
	// wait for protocol result or timeout
	select {
	case masterChallenge := <-p.result:
		log.Lvlf3("finished %s protocol, resulting challenge: %v", Name, masterChallenge)
		return masterChallenge, nil
	case <-time.After(Timeout):
		return daga.Challenge{}, fmt.Errorf("%s didn't finish in time", Name)
	}
}

// handler that is called on "slaves" upon reception of Leader's Announce message
// Step 2 of daga challenge generation protocol described in Syta - 4.7.4
func (p *Protocol) handleAnnounce(msg StructAnnounce) (err error) {
	defer func() {
		if err != nil {
			p.Done()
		}
	}()

	log.Lvlf3("%s: %s Received Leader's Announce", Name, p.ServerIdentity())
	leaderTreeNode := msg.TreeNode

	// validate request (valid + accepted) and update state
	if dagaServer, err := p.acceptRequest(&msg.OriginalRequest); err != nil {
		return errors.New(Name + ": failed to handle Leader's Announce: " + err.Error())
	} else {
		// we can safely use leader provided context, we just validated it against our independent state
		p.context = msg.OriginalRequest.Context
		p.pKClientCommitments = msg.OriginalRequest.Commitments
		p.setDagaServer(dagaServer)
	}

	// verify signature of Leader's commitment
	// FIXME WHY ?: if we trust the rosters (and the daga context)
	//  all these node-node signatures/authentication are useless since authenticity and integrity should be protected by the "DEDIS-tls" channels in Onet..
	members := p.context.Members()
	err = daga.VerifyChallengeCommitmentSignature(suite, msg.LeaderCommit, members.Y[msg.LeaderIndexInContext])
	if err != nil {
		return errors.New(Name + ": failed to handle Leader's Announce: " + err.Error())
	}

	// store it in own state for later verification of correct opening
	p.saveCommitment(0, msg.LeaderCommit)

	// create our signed commitment to our new challenge
	challengeCommit, opening, err := daga.NewChallengeCommitment(suite, p.dagaServer)
	if err != nil {
		return errors.New(Name + ": failed to handle Leader's Announce: " + err.Error())
	}

	// store our opening
	p.saveOpening(0, opening)

	// send back signed commitment to leader
	return p.SendTo(leaderTreeNode, &AnnounceReply{
		Commit: *challengeCommit,
	})
}

// QUESTION here by design some handlers are to be called only on root when all children responded,
//  what can go wrong if (if possible/makes sense)
//  some messages travels in the wrong direction, say we sent to a children (is it possible?) node some reply
//  to trigger the call of handler that is not supposed to be called on children
//  current code will panic is that ok ?

// handler that will be called by framework when Leader node has received an AnnounceReply from all other nodes (its children)
// Step 3 of daga challenge generation protocol described in Syta - 4.7.4
func (p *Protocol) handleAnnounceReply(msg []StructAnnounceReply) (err error) {
	defer func() {
		if err != nil {
			p.Done()
		}
	}()

	// remember that for correct aggregation of messages the tree must have correct shape
	log.Lvlf3("%s: Leader received all Announce replies", Name)

	// verify signatures of the commitments from all other nodes/children
	members := p.context.Members()
	for _, announceReply := range msg {
		challengeCommit := announceReply.Commit
		// verify signature of node's commitment
		err := daga.VerifyChallengeCommitmentSignature(suite, challengeCommit, members.Y[challengeCommit.Index])
		if err != nil {
			return fmt.Errorf("%s: failed to handle AnnounceReply, : %s", Name, err.Error())
		}

		// store commitment
		p.saveCommitment(challengeCommit.Index, challengeCommit)
	}

	// broadcast Leader's opening, (request other's openings)
	errs := p.Broadcast(&Open{
		LeaderOpening: p.opening(p.dagaServer.Index()),
	})
	if len(errs) != 0 {
		return fmt.Errorf("%s: broadcast of Open failed with error(s): %v", Name, errs)
	}
	return nil
}

// handler that is called on "slaves" upon reception of Leader's Open message
// Step 3.5 of daga challenge generation protocol described in Syta - 4.7.4
func (p *Protocol) handleOpen(msg StructOpen) (err error) {
	defer func() {
		if err != nil {
			p.Done()
		}
	}()

	log.Lvlf3("%s: %s Received Leader's Open", Name, p.ServerIdentity())
	// TODO nil/empty msg checks

	// verify that leader's opening correctly open its commitment
	leaderCommit := p.commitment(0)
	if !daga.CheckOpening(suite, leaderCommit.Commit, msg.LeaderOpening) {
		return fmt.Errorf("%s: failed to handle Leader's Open: wrong opening", Name)
	}

	// send our opening back to leader
	// TODO maybe check that leader is same leader as in announce.. or some other things.. ??
	ownOpening := p.opening(0)
	return p.SendTo(msg.TreeNode, &OpenReply{
		Opening: ownOpening,
		Index:   p.dagaServer.Index(),
	})
}

// handler that will be called by framework when Leader node has received an OpenReply from all other nodes (its children)
// Step 4 of daga challenge generation protocol described in Syta - 4.7.4
func (p *Protocol) handleOpenReply(msg []StructOpenReply) (err error) {
	defer func() {
		if err != nil {
			p.Done()
		}
	}()

	log.Lvlf3("%s: Leader received all Open replies", Name)

	// to figure out the node of the next-server in "ring"
	// TODO at this step would like to have a "ring built with tree" topology to just have to sendToChildren
	//  run new "subprotocol" with new tree for the finalize step ? mhhh bof..
	//  or send to everyone including self in a for loop (like was done in wolinsky/dagas), onet will dispatch locally for us..
	//  => (+) DRY a little the code and avoid having to figure out who is next node,
	//  => (-) we distance ourselves from daga paper (no longer ring communication but star)

	for _, openReply := range msg {
		p.saveOpening(openReply.Index, openReply.Opening)
	}
	//After receiving all the openings, leader verifies them and initializes the challengeCheck structure
	// TODO nicify kyber.daga "API" / previous code if possible => then clean/hide details of protocols there
	challengeCheck, err := daga.InitializeChallenge(suite, p.context, p.commitments, p.openings)
	if err != nil {
		return fmt.Errorf("%s: failed to handle OpenReply, : %s", Name, err.Error())
	}

	//Then it executes CheckUpdateChallenge, to verify again... and add its signature (TODO...pff^^  clean previous code)
	if err := daga.CheckUpdateChallenge(suite, p.context, challengeCheck, p.pKClientCommitments, p.dagaServer); err != nil {
		return fmt.Errorf("%s: failed to handle OpenReply, : %s", Name, err.Error())
	}

	// forward to next server ("ring topology")
	return p.sendToNextServer(&Finalize{
		ChallengeCheck: *challengeCheck,
	})
}

// handler that will be called by framework when node received a Finalize msg from a previous node in ring
// Step 4.5 of daga challenge generation protocol described in Syta - 4.7.4
func (p *Protocol) handleFinalize(msg StructFinalize) error {
	defer p.Done()
	log.Lvlf3("%s: %s Received Finalize", Name, p.ServerIdentity())

	// check if we are the leader
	members := p.context.Members()
	weAreNotLeader := len(msg.ChallengeCheck.Sigs) != len(members.Y) // TODO once daga API cleaned remove that...

	// Executes CheckUpdateChallenge (to verify and add signature, or verify only if we are last node/leader)
	if err := daga.CheckUpdateChallenge(suite, p.context, &msg.ChallengeCheck, p.pKClientCommitments, p.dagaServer); err != nil {
		return fmt.Errorf("%s: failed to handle Finalize, : %s", Name, err.Error())
	}

	if weAreNotLeader {
		// not all nodes have received Finalize => figure out the node of the next-server in "ring" and send to it.
		return p.sendToNextServer(&Finalize{ChallengeCheck: msg.ChallengeCheck})
	} else {
		// step 5
		// we are the leader, and all nodes already updated the challengecheck struct => Finalize the challenge
		clientChallenge, err := daga.FinalizeChallenge(p.context, &msg.ChallengeCheck)
		if err != nil {
			return fmt.Errorf("%s: failed to handle Finalize, leader failed to finalize the challenge: %s", Name, err.Error())
		}
		// make result available to service that will send it back to client
		p.result <- clientChallenge
		return nil
	}
}

// TODO see remark in protocols/utils, would be nice to share more code between daga protocols
func (p *Protocol) sendToNextServer(msg interface{}) error {
	// figure out the node of the next-server in "ring"

	// here we pass the public keys of nodes in roster instead of the ones from auth. context to simplify the
	// "ring communication", now the "ring order" is based on the indices of the nodes in context's roster instead of in context
	// like described in DAGA paper (nothing changed fundamentally).
	// if we prefer keeping the indices in context for the "ring order", (no particular reason to do so..)
	// we would need ways to map conodes/treenodes to their daga keys in order to select the next node
	// since nodes can (and probably have) multiple daga server identities (per context).
	// (see old comments in https://github.com/dedis/student_18_daga/blob/7d32acf216cbdea230d91db6eee633061af58caf/daga_login/protocols/DAGAChallengeGeneration/protocol.go#L411-L417)
	// TODO if we keep current solution, combine indexOf and nextnode in a cleverer algo to use a single loop
	ownIndex, _ := dagacothority.IndexOf(p.context.Roster.Publics(), p.Public())
	if nextServerTreeNode, err := protocols.NextNode(ownIndex, p.context.Roster.Publics(), p.Tree().List()); err != nil {
		return fmt.Errorf("sendToNextServer: %s", err)
	} else {
		// send to next server in ring
		return p.SendTo(nextServerTreeNode, msg)
	}
}
