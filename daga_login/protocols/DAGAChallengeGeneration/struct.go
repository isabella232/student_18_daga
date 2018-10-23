package protocol

import (
	"github.com/dedis/onet"
	"github.com/dedis/student_18_daga/sign/daga"
)

/*
Struct holds the messages that will be sent around in the protocol. You have
to define each message twice: once the actual message, and a second time
with the `*onet.TreeNode` embedded. The latter is used in the handler-function
so that it can find out who sent the message.
*/

// Name can be used from other packages to refer to this protocol.
const Name = "DAGAChallengeGeneration"

// Announce is sent from Leader upon reception of a client request.
// it request that all other nodes generate a new challenge and send back a signed commitment to their challenge.
type Announce struct {
	daga.Challenge
}

// StructAnnounce just contains Announce and the data necessary to identify and
// process the message in the sda framework.
// QUESTION not sure to understand why needed
type StructAnnounce struct {
	*onet.TreeNode
	Announce
}
