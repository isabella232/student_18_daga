package DAGAChallengeGeneration

import (
	"github.com/dedis/kyber"
	"github.com/dedis/onet"
	"github.com/dedis/student_18_daga/daga_login"
	"github.com/dedis/student_18_daga/sign/daga"
)

/*
Struct holds the messages that will be sent around in the protocols. You have
to define each message twice: once the actual message, and a second time
with the `*onet.TreeNode` embedded. The latter is used in the handler-function
so that it can find out who sent the message.
*/

// Name can be used from other packages to refer to this protocols.
const Name = "DAGAChallengeGeneration"

// Announce is sent from Leader upon reception of a client request.
// it request that all other nodes generate a new challenge and send back a signed commitment to their challenge.
type Announce struct {
	LeaderCommit        daga.ChallengeCommitment    // contains the signed commitment of the Leader

	LeaderIndexInContext int  // to allow the nodes to pick correct public key in context
	// original request:
	// the PKClient commitments (to tie them to the signatures issued at Finalize-time and avoid malicious agents being tempted to cheat/alter proof transcript)
	// the context (of the original client request) (and hence the server keys used to verify signatures and eventually for the other nodes to check if they accept the request too)
	OriginalRequest daga_login.PKclientCommitments
}

// StructAnnounce just contains Announce and the data necessary to identify and
// process the message in the framework.
// QUESTION not sure to understand why needed => hack that framework uses to communicate sender info ? cannot hide this in framework instead ?)
type StructAnnounce struct {
	*onet.TreeNode // sender
	Announce
}

// AnnounceReply is sent from all nodes back to the Leader, it contains what the leader asked, their signed commitment to a Challenge
type AnnounceReply struct {
	Commit daga.ChallengeCommitment
}

// StructAnnounceReply just contains AnnounceReply and the data necessary to identify and
// process the message in the framework.
type StructAnnounceReply struct {
	*onet.TreeNode
	AnnounceReply
}

// Open is sent from Leader upon reception and verification of all AnnounceReply.
// it request that all other nodes send back their openings
type Open struct {
	LeaderOpening kyber.Scalar
}

// StructOpen just contains Open and the data necessary to identify and
// process the message in the framework.
type StructOpen struct {
	*onet.TreeNode
	Open
}

// OpenReply is sent from all nodes back to the Leader, it contains what the leader asked, their opening of the previously sent commitment
type OpenReply struct {
	Opening kyber.Scalar
	Index   int // index in auth. context
}

// StructOpenReply just contains OpenReply and the data necessary to identify and
// process the message in the framework.
type StructOpenReply struct {
	*onet.TreeNode
	OpenReply
}

// Finalize is sent from node to node, starting from the leader and back to the leader
// to collect signatures of the computed master challenge etc..
type Finalize struct {
	ChallengeCheck daga.ChallengeCheck
}

// StructFinalize just contains Finalize and the data necessary to identify and
// process the message in the framework.
type StructFinalize struct {
	*onet.TreeNode
	Finalize
}
