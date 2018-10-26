package DAGAChallengeGeneration

// FIXME better namings + remember to address https://github.com/dedis/student_18_daga/issues/24
// QUESTION not sure if each protocol deserve its own package but if I put them all in same package (say protocol) will need to change a little the template conventions
// QUESTION : purpose of shutdown, cleanup when protocol done ?, automatically called or manually called ?

/*
The `NewProtocol` method is used to define the protocol and to register
the handlers that will be called if a certain type of message is received.
The handlers will be treated according to their signature.

The protocol-file defines the actions that the protocol needs to do in each
step. The root-node will call the `Start`-method of the protocol. Each
node will only use the `Handle`-methods, and not call `Start` again.

TODO improve documentation, lacks lots of documentation or not up to date.

*/

import (
	"errors"
	"fmt"
	"github.com/dedis/kyber"
	"github.com/dedis/onet/network"
	"github.com/dedis/student_18_daga/daga_login"
	"github.com/dedis/student_18_daga/sign/daga"
	"time"

	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
)

var suite = daga.NewSuiteEC()

// TODO educated timeout formula that scale with number of nodes etc..
const Timeout = 5 * time.Second

func init() {
	network.RegisterMessage(Announce{})  // register here first message of protocol s.t. every node know how to handle them (before NewProtocol has a chance to register all the other, since it won't be called if onet doesnt know what do to with them)
	// QUESTION protocol is tied to service => according to documentation I need to call Server.ProtocolRegisterName
	// QUESTION Where ?
	// QUESTION need more info on all of this works and what are the possible scenarios, documentation not clear enough nor up to date
	onet.GlobalProtocolRegister(Name, NewProtocol) // FIXME remove
}

// DAGAChallengeGenerationProtocol holds the state of the challenge generation protocol.
type DAGAChallengeGenerationProtocol struct {
	*onet.TreeNodeInstance
	result      chan daga.Challenge
	commitments []daga.ChallengeCommitment // on the leader/root: to store every commitments at correct index (in auth. context), on the children to store leaderCommitment at 0
	openings    []kyber.Scalar             // on the leader/root: to store every opening at correct index (in auth. context), on the children store own opening at 0

	dagaServer daga.Server        // the daga server of this protocol instance, should be populated from infos taken from Service at protocol creation time
	context    daga_login.Context // the context of the client request (set by leader when received from API call and then propagated to other instances as part of the announce message)
}

// NewProtocol initialises the structure for use in one round (at the root/leader), callback passed to onet upon protocol registration
// and used to instantiate protocol instances, if service.NewProtocol returns nil, nil this one will be called on children too.
func NewProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	t := &DAGAChallengeGenerationProtocol{
		TreeNodeInstance: n,
	}
	for _, handler := range []interface{}{t.HandleAnnounce, t.HandleAnnounceReply,
										  t.HandleOpen, t.HandleOpenReply,
										  t.HandleFinalize} {
		if err := t.RegisterHandler(handler); err != nil {
			return nil, errors.New("couldn't register handler: " + err.Error())
		}
	}
	return t, nil
}

// setup function that needs to be called after protocol creation on Leader/root (and only at that time !)
func (p *DAGAChallengeGenerationProtocol) LeaderSetup(reqContext daga_login.Context, dagaServer daga.Server) {
	if p.commitments != nil || p.openings != nil || p.dagaServer != nil || p.result != nil {
		log.Panic("protocol setup: LeaderSetup called on an already initialized node.")
	}
	p.setContext(reqContext)
	p.setDagaServer(dagaServer)
	p.commitments = make([]daga.ChallengeCommitment, len(p.Tree().List()))
	p.openings = make([]kyber.Scalar, len(p.Tree().List()))
	p.result = make(chan daga.Challenge)
}

// setup function that needs to be called after protocol creation on other tree nodes
func (p *DAGAChallengeGenerationProtocol) ChildrenSetup(dagaServer daga.Server) {
	if p.commitments != nil || p.openings != nil || p.dagaServer != nil || p.result != nil {
		log.Panic("protocol setup: ChildrenSetup called on an already initialized node.")
	}
	p.setDagaServer(dagaServer)
	p.commitments = make([]daga.ChallengeCommitment, 1)
	p.openings = make([]kyber.Scalar, 1)
}

// setter that service needs to call to give to the protocol instance "which daga.Server it is"
func (p *DAGAChallengeGenerationProtocol) setDagaServer(dagaServer daga.Server) {
	if dagaServer == nil {//|| reflect.ValueOf(dagaServer).IsNil() {
		log.Panic("protocol setup: nil daga server")
	}
	p.dagaServer = dagaServer
}

// setter that service needs to call (on leader only) to give to the protocol instance the context of the original PKClient request.
func (p *DAGAChallengeGenerationProtocol) setContext(reqContext daga_login.Context) {
	// TODO maybe armor with sanity checks
	p.context = reqContext
}

// method called to update state of the protocol (add opening) (sanity checks)
func (p *DAGAChallengeGenerationProtocol) saveOpening(index int, opening kyber.Scalar) {
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
func (p *DAGAChallengeGenerationProtocol) opening(index int) kyber.Scalar {
	if index >= len(p.openings) {
		log.Panicf("index (%d) out of bound while getting openings from state, len(p.openings) = %d", index, len(p.openings))
	}
	if p.openings[index] == nil {
		log.Panicf("nil at p.openings[%d]", index)
	}
	return p.openings[index]
}

// method called to update state of the protocol (add commitment) (add only commitment whose signature is verified !)
func (p *DAGAChallengeGenerationProtocol) saveCommitment(index int, commitment daga.ChallengeCommitment) {
	if index >= len(p.commitments) {
		log.Panicf("index (%d) out of bound while setting commitment in state, len(p.commitment) = %d", index, len(p.commitments))
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
func (p *DAGAChallengeGenerationProtocol) commitment(index int) daga.ChallengeCommitment {
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
func (p *DAGAChallengeGenerationProtocol) Start() error {

	if len(p.Children()) != len(p.context.ServersSecretsCommitments())-1 {
		return errors.New(Name + ": failed to start: tree has invalid shape")
	}
	log.Lvlf3("leader (%s) started DAGA ChallengeGenerationProtocol", p.ServerIdentity())

	// create leader challenge, signed commitment and openning
	leaderChallengeCommit, leaderOpenning, err := daga.NewChallengeCommitment(suite, p.dagaServer)
	if err != nil {
		return errors.New(Name + ": failed to start: " + err.Error())
	}
	// save commitment and opening in state
	p.saveOpening(p.dagaServer.Index(), leaderOpenning)
	p.saveCommitment(p.dagaServer.Index(), *leaderChallengeCommit)

	// broadcast Announce requesting that all other nodes do the same and send back their signed commitments.
	// when leader create and start protocol upon reception of PKclient commitments (service)
	// it will populate Tree with the auth. Context/roster (only nodes that are part of the daga auth. context)
	// TODO do work in new goroutine and send in parallel as was done in skipchain
	errs := p.Broadcast(&Announce{
		LeaderCommit: *leaderChallengeCommit,
		Context:      *p.context.NetEncode(), // TODO maybe use setconfig for that purpose instead but... pff..
	})
	if len(errs) != 0 {
		return fmt.Errorf(Name+": failed to start: "+"broadcast of Announce failed with error(s): %v", errs)
	}
	return nil
}

// Wait for protocol result or timeout, must be called on root instance
func (p *DAGAChallengeGenerationProtocol) WaitForResult() (daga.Challenge, error) {
	if p.result == nil {
		log.Panic("WaitForResult called on an uninitialized protocol instance or non root/Leader protocol instance")
	}
	// wait for protocol result or timeout
	select {
	case masterChallenge := <-p.result:
		log.Lvlf3("finished DAGAChallengeGeneration protocol, resulting challenge: %v", masterChallenge)
		// FIXME store somewhere (or avoid to by another trick) the commitments and challenge to check later the proof transcript validity !!
		// FIXME => need way to link PKCLient call with corresponding Auth call...
		// FIXME see https://github.com/dedis/student_18_daga/issues/24 for discussion and solutions
		// FIXME TL:DR "store state in clients", have the commitments be signed by the servers during challenge generation protocol (like we do for the challenge)
		// FIXME and request that client send them back later as part of transcript
		// FIXME for now don't store anything and continue to blindly trust client....
		return masterChallenge, nil
	case <-time.After(Timeout):
		return daga.Challenge{}, errors.New("DAGA challenge generation didn't finish in time")
	}
}

// handler that is called on "slaves" upon reception of Leader's Announce message
// Step 2 of daga challenge generation protocol described in Syta - 4.7.4
func (p *DAGAChallengeGenerationProtocol) HandleAnnounce(msg StructAnnounce) error {

	log.Lvlf3("%s: Received Leader's Announce", Name)
	leaderTreeNode := msg.TreeNode

	// verify signature of Leader's commitment
	// FIXME fetch the key from the auth. context instead !
	// FIXME => have the context be passed from service to protocol on start then context !ok
	// FIXME propagated to other instances in announce message !ok
	// FIXME/TODO then validated before proceeding see discussion in https://github.com/dedis/student_18_daga/issues/25

	if context, err := msg.Context.NetDecode(); err != nil {
		return errors.New(Name + ": failed to handle Leader's Announce: cannot decode context:" + err.Error())
	} else {
		p.setContext(context)
	}

	err := daga.VerifyChallengeCommitmentSignature(suite, msg.LeaderCommit, leaderTreeNode.ServerIdentity.Public)
	if err != nil {
		return errors.New(Name + ": failed to handle Leader's Announce: " + err.Error())
	}

	// store it in own state for later verification of correct opening
	p.saveCommitment(0, msg.LeaderCommit)

	// QUESTION of style : better to have everything here and start calls announce and here we test whether we are leader or like I'v done (DRYness, can have commit generation at unique place)
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

// QUESTION here by design some handlers are designed to be called only on root when all children responded, what can go wrong if (if possible/makes sense)
// QUESTION some messages travels in the wrong direction, say we sent to a children (is it possible?) node some reply to trigger the call of handler that is not supposed to be called on children
// QUESTION current code will panic is that ok ?

// handler that will be called by framework when Leader node has received an AnnounceReply from all other nodes (its children)
// Step 3 of daga challenge generation protocol described in Syta - 4.7.4
func (p *DAGAChallengeGenerationProtocol) HandleAnnounceReply(msg []StructAnnounceReply) error {
	// remember that for correct aggregation of messages the tree must have correct shape
	log.Lvlf3("%s: Leader received all Announce replies", Name)

	// verify signatures of the commitments from all other nodes/children
	for _, announceReply := range msg {
		challengeCommit := announceReply.Commit
		// verify signed commitment of node
		// FIXME fetch the key from the auth. context instead ! (using index info in challengecommit)
		// FIXME => have the context be passed from service to protocol on start then context
		// FIXME propagated to other instances in announce message
		// FIXME then validated before proceeding see discussion in https://github.com/dedis/student_18_daga/issues/25
		err := daga.VerifyChallengeCommitmentSignature(suite, challengeCommit, announceReply.ServerIdentity.Public)
		if err != nil {
			return fmt.Errorf("%s: failed to handle AnnounceReply, : %s", Name, err.Error())
		}

		// store commitments
		p.saveCommitment(challengeCommit.Index, challengeCommit)
	}

	// broadcast Leader's opening, (request other's openings)
	errs := p.Broadcast(&Open{
		LeaderOpening: p.opening(p.dagaServer.Index()),
	})
	if len(errs) != 0 {
		return fmt.Errorf("broadcast of Open failed with error(s): %v", errs)
	}
	return nil
}

// handler that is called on "slaves" upon reception of Leader's Open message
// Step 3.5 of daga challenge generation protocol described in Syta - 4.7.4
func (p *DAGAChallengeGenerationProtocol) HandleOpen(msg StructOpen) error {

	log.Lvlf3("%s: Received Leader's Open", Name)
	// TODO nil/empty msg checks
	// verify that leader opening correctly open its commitment
	leaderCommit := p.commitment(0)
	if !daga.CheckOpening(suite, leaderCommit.Commit, msg.LeaderOpening) {
		return fmt.Errorf("%s: failed to handle Leader's Open: wrong opening", Name)
	}

	// send our opening back to leader
	// TODO maybe check that leader is same leader as in annouce.. or some other things.. ??
	ownOpening := p.opening(0)
	return p.SendTo(msg.TreeNode, &OpenReply{
		Opening: ownOpening,
		Index:   p.dagaServer.Index(),
	})
}

// handler that will be called by framework when Leader node has received an OpenReply from all other nodes (its children)
// Step 4 of daga challenge generation protocol described in Syta - 4.7.4
func (p *DAGAChallengeGenerationProtocol) HandleOpenReply(msg []StructOpenReply) error {

	log.Lvlf3("%s: Leader received all Open replies", Name)

	// to figure out the node of the next-server in "ring"
	_, Y := p.context.Members()
	nextServerIndex := (p.dagaServer.Index() + 1) % len(Y)
	var nextServerTreeNode *onet.TreeNode

	//After receiving all the openings, leader verifies them and initializes the challengeCheck structure
	for _, openReply := range msg {
		p.saveOpening(openReply.Index, openReply.Opening)
		if openReply.Index == nextServerIndex {
			nextServerTreeNode = openReply.TreeNode
		}
	}
	// TODO nicify daga API if possible
	challengeCheck, err := daga.InitializeChallenge(suite, p.context, p.commitments, p.openings)
	if err != nil {
		return fmt.Errorf("%s: failed to handle OpenReply, : %s", Name, err.Error())
	}

	//Then it executes CheckUpdateChallenge, to verify again(TODO...pff^^  clean previous student code) and add signature
	if err := daga.CheckUpdateChallenge(suite, p.context, challengeCheck, p.dagaServer); err != nil {
		return fmt.Errorf("%s: failed to handle OpenReply, : %s", Name, err.Error())
	}
	// forward to next server ("ring topology")
	return p.SendTo(nextServerTreeNode, &Finalize{
		ChallengeCheck: *challengeCheck,
	})
}

// handler that will be called by framework when node received a Finalize msg from a previous node in ring
// Step 4 of daga challenge generation protocol described in Syta - 4.7.4
func (p *DAGAChallengeGenerationProtocol) HandleFinalize(msg StructFinalize) error {

	log.Lvlf3("%s: Received Finalize", Name)

	// check if we are the leader (last node..)
	_, Y := p.context.Members()
	weAreNotLeader := len(msg.ChallengeCheck.Sigs) != len(Y)

	// Executes CheckUpdateChallenge
	if err := daga.CheckUpdateChallenge(suite, p.context, &msg.ChallengeCheck, p.dagaServer); err != nil {
		return fmt.Errorf("%s: failed to handle Finalize, : %s", Name, err.Error())
	}

	if weAreNotLeader {
		// not all nodes have received Finalize => send to next node in ring

		// figure out the node of the next-server in "ring"
		nextServerIndex := (p.dagaServer.Index() + 1) % len(Y)
		nextServerPubKey := Y[nextServerIndex]
		nextServerTreeNode := func() *onet.TreeNode {
			for _, treeNode := range p.Tree().List() {
				// TODO use indexOf helper
				// TODO for now ok but if in future we allow nodes to have multiple daga.Server identities => doesn't work, we need sort of a directory service or protocol..
				// TODO kind of service that answer with a signature when called with a publicKey areYou(pubKey)? => {yes, sign} | { no }
				// TODO what would be a real solution to get correct treenode (if multiple daga identitities) ?
				if treeNode.ServerIdentity.Public.Equal(nextServerPubKey) {
					return treeNode
				}
			}
			return nil
		}()
		if nextServerTreeNode == nil {
			fmt.Errorf("%s: failed to handle Finalize, failed to find next node: ", Name)
		}
		return p.SendTo(nextServerTreeNode, &Finalize{
			ChallengeCheck: msg.ChallengeCheck,
		})
	} else {
		// we are the leader, and all nodes already updated the challengecheck struct => Finalize the challenge
		clientChallenge, err := daga.FinalizeChallenge(p.context, &msg.ChallengeCheck)
		if err != nil {
			fmt.Errorf("%s: failed to handle Finalize, leader failed to finalize the challenge: %s", Name, err.Error())
		}
		// make result available to service that will send it back to client
		p.result <- clientChallenge
		return nil
	}
}
