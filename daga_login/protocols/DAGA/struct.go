package DAGA

import (
	"github.com/dedis/onet"
	"github.com/dedis/student_18_daga/daga_login"
)

/*
this file holds the messages that will be sent around in the DAGA server's protocol.
each message has to be defined twice: once the actual message, and a second time
with a `*onet.TreeNode` embedded. The latter is used in the handler-function
so that it can find out who sent the message.
*/

// Name can be used from other packages to refer to this protocols.
const Name = "DAGA_Server_protocol"

// represents a daga.ServerMessage that is not yet completed by all servers
type ServerMsg struct {
	daga_login.AuthReply
}

// StructServerMsg just contains ServerMsg and the data necessary to identify and
// process the message in the framework.
type StructServerMsg struct {
	*onet.TreeNode // sender
	ServerMsg
}

// represents a daga.ServerMessage that is completed by all servers and ready to be sent to client
type FinishedServerMsg struct {
	daga_login.AuthReply
}

// StructServerMsg just contains FinishedServerMsg and the data necessary to identify and
// process the message in the framework.
type StructFinishedServerMsg struct {
	*onet.TreeNode // sender
	FinishedServerMsg
}
