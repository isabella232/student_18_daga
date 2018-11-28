package daga_login

/*
This holds the messages used to communicate with the daga service over the network.
this file has 2 purposes,
	- provide the go data-structures used in the daga cothority API
	- provide their description: => the file can be used as input to proto.awk that
									can transpile it into a proto file (protobuf) for interoperability.

this means that the content of the file need to stay proto.awk friendly:
	- only struct types, no type aliases,
	- no anonymous fields and types
	- no same line declaration of fields
    - no functions/methods,
	- no "same line comments"
	- no blank lines/"holes inside the struct definitions

additionally this means that the data-structures need to stay onet/protobuf friendly:
	- only public/exported fields
	- no interface fields (in general.., kyber.Point/Scalar ok, see how onet package handle encoding/decoding etc.)
*/

import (
	"github.com/dedis/kyber"
	"github.com/dedis/onet"
)

// PROTOSTART
// package daga_login;
// type :ServiceID:bytes
// type :ContextID:bytes
// import "onet.proto";

// CreateContext will initiate the context generation protocol that will result in a CreateContextReply
type CreateContext struct {
	// used to identify 3rd-party service making the request (maybe we don't need to strictly identify but easier for now, later can rely on other schemes)
	ServiceID       ServiceID
	Signature       []byte
	SubscribersKeys []kyber.Point
	// all the nodes that the 3rd-party service wants to include in its DAGA cothority
	DagaNodes *onet.Roster
}

type CreateContextReply struct {
	Context Context
}

// PKclientCommitments will initiate the challenge generation protocol that will result (on success) in a PKclientChallenge
type PKclientCommitments struct {
	// to early reject auth requests part of context that the server doesn't care about
	Context     Context
	Commitments []kyber.Point
}

// copy of daga.Challenge to make awk proto generation happy (don't have proto generation in sign/daga)
// TODO(/never): (find better solution) or why not using same proto.go generation procedure in sign/daga etc..
type PKclientChallenge struct {
	Cs   kyber.Scalar
	Sigs []ServerSignature
}

// copy of daga.ServerSignature to make awk proto generation happy (don't have proto generation in sign/daga)
type ServerSignature struct {
	Index int
	Sig   []byte
}

// Auth will start the authentication of client that will result (on success) in an AuthReply
// it provides a net (and awk friendly) compatible representation of the daga.AuthenticationMessage struct
// (which embeds a context which is an interface)
type Auth struct {
	Context  Context
	SCommits []kyber.Point
	T0       kyber.Point
	Proof    ClientProof
}

// AuthReply provides a net (and awk friendly) compatible representation of the daga.ServerMessage struct
// (which embeds an auth message struct which embeds a context which ..)
// FIXME don't reply with server message but only tag (authentified/endorsed by all servers) and fix the "dumbnesses" in daga.server..
type AuthReply struct {
	Request Auth
	Tags    []kyber.Point
	Proofs  []ServerProof
	Indexes []int
	Sigs    []ServerSignature
}

// copy of daga.ServerProof to make awk proto generation happy (don't have proto generation in sign/daga)
// TODO see FIXME above
type ServerProof struct {
	T1 kyber.Point
	T2 kyber.Point
	T3 kyber.Point
	C  kyber.Scalar
	R1 kyber.Scalar
	R2 kyber.Scalar
}

// Context implements the daga.AuthenticationContext interface
// and embed a corresponding Onet roster (how to reach the DAGA servers)
type Context struct {
	ContextID ContextID
	// ID of the 3rd-party service that use this context for auth. purposes
	ServiceID ServiceID
	// signatures that show endorsement of the context by all the daga servers
	Signatures [][]byte
	// awk friendly version of daga.MinimumAuthenticationContext { daga.Members, R, H } that was previously relied upon to implement the interface
	X      []kyber.Point
	Y      []kyber.Point
	R      []kyber.Point
	H      []kyber.Point
	Roster *onet.Roster
}

// copy of daga.Challenge to make awk proto generation happy (don't have proto generation in sign/daga)
type ClientProof struct {
	Cs PKclientChallenge
	T  []kyber.Point
	C  []kyber.Scalar
	R  []kyber.Scalar
}
