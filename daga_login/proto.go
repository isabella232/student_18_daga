package daga_login

/*
This holds the messages used to communicate with the daga service over the network.
*/

import (
	"github.com/dedis/kyber"
	"github.com/dedis/onet"
	"github.com/dedis/student_18_daga/sign/daga"
	"github.com/satori/go.uuid"
)

// CreateContext will initiate the context generation protocol that will result in a CreateContextReply
type CreateContext struct {
	// used to identify 3rd-party service making the request (maybe we don't need to strictly identify but easier for now, later can rely on other schemes)
	ServiceID       ServiceID
	Signature []byte
	SubscribersKeys []kyber.Point
	// all the nodes that the 3rd-party service wants to include in its DAGA cothority
	DagaNodes *onet.Roster
}

type CreateContextReply struct {
	Context Context
}

// PKclientCommitments will initiate the challenge generation protocol that will result in a PKclientChallenge
type PKclientCommitments struct {
	// to early reject auth requests part of context that the server doesn't care about
	Context     Context
	Commitments []kyber.Point
}

type PKclientChallenge daga.Challenge

// Auth will start the authentication of client that will result (on success) in an AuthReply
type Auth NetAuthenticationMessage

// FIXME don't reply with server message but only tag (authentified/endorsed by all servers) and fix the "dumbnesses" in daga.server..
type AuthReply NetServerMessage

// FIXME investigate if satori is still the package to use, saw claims that it should be deprecated in favor of newer forks
// ID of 3rd party service (that use DAGA as its auth. mechanism, don't confuse with Onet.ServiceID)
type ServiceID uuid.UUID
type ContextID uuid.UUID

// Context implements the daga.AuthenticationContext interface
// and embed a corresponding Onet roster (how to reach the DAGA servers)
type Context struct {
	ContextID ContextID
	// ID of the 3rd-party service that use this context for auth. purposes
	ServiceID  ServiceID
	// signatures that show endorsement of the context by all the daga servers
	Signatures [][]byte
	daga.MinimumAuthenticationContext
	*onet.Roster
}

// NetAuthenticationMessage provides a net compatible representation of the daga.AuthenticationMessage struct
// (which embeds a context which is an interface)
type NetAuthenticationMessage struct {
	Context  Context
	SCommits []kyber.Point
	T0       kyber.Point
	Proof    daga.ClientProof
}

// NetServerMessage provides a net compatible representation of the daga.ServerMessage struct
// (which embeds an auth message struct which embeds a context which ..)
type NetServerMessage struct {
	Request NetAuthenticationMessage
	Tags    []kyber.Point
	Proofs  []daga.ServerProof
	Indexes []int
	Sigs    []daga.ServerSignature
}