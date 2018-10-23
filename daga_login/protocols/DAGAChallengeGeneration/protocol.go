package protocol

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
	"github.com/dedis/student_18_daga/sign/daga"

	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
)

var suite = daga.NewSuiteEC()

func init() {
	network.RegisterMessage(Announce{})
	onet.GlobalProtocolRegister(Name, NewProtocol)
}

// DAGAChallengeGenerationProtocol holds the state of the challenge generation protocol.
type DAGAChallengeGenerationProtocol struct {
	*onet.TreeNodeInstance
}

// Check that *DAGAChallengeGenerationProtocol implements onet.ProtocolInstance
var _ onet.ProtocolInstance = (*DAGAChallengeGenerationProtocol)(nil)

// NewProtocol initialises the structure for use in one round
func NewProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	t := &DAGAChallengeGenerationProtocol{
		TreeNodeInstance: n,
	}
	for _, handler := range []interface{}{t.HandleAnnounce} {
		if err := t.RegisterHandler(handler); err != nil {
			return nil, errors.New("couldn't register handler: " + err.Error())
		}
	}
	return t, nil
}

// Start sends the Announce-message to all children
func (p *DAGAChallengeGenerationProtocol) Start() error {
	log.Lvl3("Leader (%s) Started DAGA ChallengeGenerationProtocol", p.ServerIdentity())
	return p.HandleAnnounce(StructAnnounce{p.TreeNode(), Announce{}})
}

// HandleAnnounce is the first message and is used to send Announce to all nodes (see Announce)
func (p *DAGAChallengeGenerationProtocol) HandleAnnounce(msg StructAnnounce) error {
	// QUESTION am I right (the StructAnnounce.TreeNode contains the sender node ?)
	// QUESTION are there more educated ways to achieve this ?
	if msg.TreeNode.ID == p.TreeNode().ID {
		// sender is self => we are the starting node/Leader
		log.Lvl3("Leader announce")
		// when leader create and start protocol upon reception of PKclient commitments
		// it will populate Tree with the auth. Context/roster (only nodes that are part of the daga auth. context)
		// announce, request that all other nodes in Tree do their job of creating a challenge and sending back a signed commitment
		for _, treeNode := range p.Tree().List() {
			if treeNode.ID != p.TreeNode().ID {
				p.SendTo(treeNode, &msg.Announce)
				log.Lvl3("announce sent to:", treeNode.ServerIdentity)
			}
		}
		// TODO create challenge, commitment signature etcc.. and update state
		// TODO FIXME see if can use a more elegant solution than figuring what server we are everytime....
		// TODO FIXME need context OR daga server infos to continue...(if context know can build server)
		dagaServer := daga.NewServer(suite, )
		leaderChallengeCommit, leaderOpenning, err := daga.NewChallengeCommitment(suite)
	} else {
		// sender is Leader
		// TODO create challenge
		// TODO sign
		// TODO reply
	}


	return nil
}

//// HandleReply is the message going up the tree and holding a counter
//// to verify the number of nodes.
//func (p *TemplateProtocol) HandleReply(reply []StructReply) error {
//	defer p.Done()
//
//	children := 1
//	for _, c := range reply {
//		children += c.ChildrenCount
//	}
//	log.Lvl3(p.ServerIdentity().Address, "is done with total of", children)
//	if !p.IsRoot() {
//		log.Lvl3("Sending to parent")
//		return p.SendTo(p.Parent(), &Reply{children})
//	}
//	log.Lvl3("Root-node is done - nbr of children found:", children)
//	p.ChildCount <- children  // FIXME blocks when #nodes = 1 (why ?)
//	return nil
//}
