package DAGA

import (
	"github.com/dedis/onet"
	"github.com/dedis/student_18_daga/daga_login"
)

/*
Struct holds the messages that will be sent around in the protocols. You have
to define each message twice: once the actual message, and a second time
with the `*onet.TreeNode` embedded. The latter is used in the handler-function
so that it can find out who sent the message.
*/

// Name can be used from other packages to refer to this protocols.
const Name = "DAGA_Server_protocol"

// TODO
type ServerMsg struct {
	daga_login.NetServerMessage
}

// StructServerMsg just contains ServerMsg and the data necessary to identify and
// process the message in the framework.
// QUESTION not sure to understand why needed => hack that framework uses to communicate sender info ? cannot hide this in framework instead ?)
type StructServerMsg struct {
	*onet.TreeNode // sender
	ServerMsg
}

// TODO
type FinishedServerMsg struct {
	daga_login.NetServerMessage
}

// StructServerMsg just contains FinishedServerMsg and the data necessary to identify and
// process the message in the framework.
// QUESTION not sure to understand why needed => hack that framework uses to communicate sender info ? cannot hide this in framework instead ?)
type StructFinishedServerMsg struct {
	*onet.TreeNode // sender
	FinishedServerMsg
}
