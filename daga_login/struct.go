package daga_login

/*
This holds the messages used to communicate with the service over the network.
*/

import (
	"github.com/dedis/onet"
	"github.com/dedis/onet/network"
)

// We need to register all messages so the network knows how to handle them.
func init() {
	network.RegisterMessages(
		Count{}, CountReply{},
		Clock{}, ClockReply{},
		PKclientCommitments{}, PKclientChallenge{},
		Auth{}, AuthReply{},
	)
}

const (
	// ErrorParse indicates an error while parsing the protobuf-file.
	ErrorParse = iota + 4000
)

// Clock will run the tepmlate-protocol on the roster and return
// the time spent doing so.
type Clock struct {
	Roster *onet.Roster
}

// ClockReply returns the time spent for the protocol-run.
type ClockReply struct {
	Time     float64
	Children int
}

// Count will return how many times the protocol has been run.
type Count struct {
}

// CountReply returns the number of protocol-runs
type CountReply struct {
	Count int
}

// PKclientCommitments will initiate the challenge generation protocol that will result in a PKclientChallenge
type PKclientCommitments struct {
	Data []NetPoint
}

type PKclientChallenge NetChallenge

type Auth NetAuthenticationMessage

type AuthReply NetServerMessage