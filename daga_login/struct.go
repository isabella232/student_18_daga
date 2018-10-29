package daga_login

/*
This holds the messages used to communicate with the service over the network.
*/

import (
	"github.com/dedis/kyber"
	"github.com/dedis/onet/network"
	"github.com/dedis/student_18_daga/sign/daga"
)

// We need to register all messages so the network knows how to handle/marshall/unmarshal them.
func init() {
	network.RegisterMessages(
		PKclientCommitments{}, PKclientChallenge{},
		Auth{}, AuthReply{},
	)
}

const (
	// ErrorParse indicates an error while parsing the protobuf-file.
	ErrorParse = iota + 4000
)

// PKclientCommitments will initiate the challenge generation protocol that will result in a PKclientChallenge
type PKclientCommitments struct {
	Context NetContext // to early reject auth requests for context that the server doesn't care about
	Data    []kyber.Point
}

type PKclientChallenge daga.Challenge

type Auth NetAuthenticationMessage

type AuthReply NetServerMessage
