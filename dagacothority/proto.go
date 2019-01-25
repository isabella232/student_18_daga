package dagacothority

/*
This holds the messages used to communicate with the daga service over the network.
this file has 2 purposes,
	- provide the go data-structures used in the daga cothority API
	- provide their description: => the file can be used as input to proto.awk that
									can transpile it into a proto file (protobuf) for interoperability with other languages/frameworks.

this means that the content of the file need to stay proto.awk friendly:
	- only struct types, no type aliases,
	- no anonymous fields and types
	- no same line declaration of multiple fields
    - no functions/methods,
	- no "same line comments"
	- no blank lines/"holes inside the struct definitions

additionally this means that the data-structures need to stay onet/protobuf friendly:
	- only public/exported fields
	- no interface fields (in general.., kyber.Point/Scalar ok, see how onet package handle encoding/decoding of interfaces etc.)
*/

import (
	"go.dedis.ch/kyber"
	"github.com/dedis/onet"
)

// PROTOSTART
// package dagacothority;
// type :ServiceID:bytes
// type :ContextID:bytes
// import "onet.proto";

// CreateContext initiates the context generation protocol that will result in a CreateContextReply
type CreateContext struct {
	// used to identify 3rd-party service making the request (maybe we don't need to strictly identify but easier for now, later can rely on other schemes)
	ServiceID       ServiceID
	Signature       []byte
	SubscribersKeys []kyber.Point
	// all the nodes that the 3rd-party service wants to include in its DAGA cothority
	DagaNodes *onet.Roster
}

// CreateContextReply is the reply to a CreateContext request ... (yes looks like I'll stop trying to satisfy golint quickly ^^)
type CreateContextReply struct {
	Context Context
}

// PKclientCommitments initiates the challenge generation protocol that will result (on success) in a PKclientChallenge
type PKclientCommitments struct {
	// to early reject auth requests part of context that the server doesn't care about
	Context     Context
	Commitments []kyber.Point
}

// PKclientChallenge is a copy of daga.Challenge to make awk proto generation happy (don't have proto generation in sign/daga + awk doesn't like type aliases)
// TODO: (find better solution) or why not using same proto.go generation procedure in sign/daga etc..
type PKclientChallenge struct {
	Cs   kyber.Scalar
	Sigs []ServerSignature
}

// ServerSignature is a copy of daga.ServerSignature to make awk proto generation happy (don't have proto generation in sign/daga)
type ServerSignature struct {
	Index int
	Sig   []byte
}

// Auth will start the authentication of client that will result (on success) in an AuthReply
// it provides a net (and awk friendly) compatible representation of the daga.AuthenticationMessage struct
// (which embeds a context which is an interface) // TODO keep an eye on the new features, interface marshaller etc.. probably oportunities to simplify those structs later
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

// ServerProof is a copy of daga.ServerProof to make awk proto generation happy (don't have proto generation in sign/daga)
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
	// awk friendly version of daga.MinimumAuthenticationContext { daga.Members, R, H } that was previously relied upon to implement the interface TODO: create proto files for sign/daga and keep original intent.
	X      []kyber.Point
	Y      []kyber.Point
	R      []kyber.Point
	H      []kyber.Point
	Roster *onet.Roster
}

// ClientProof is a copy of daga.Challenge to make awk proto generation happy (don't have proto generation in sign/daga)
type ClientProof struct {
	Cs PKclientChallenge
	T  []kyber.Point
	C  []kyber.Scalar
	R  []kyber.Scalar
}

type Traffic struct {
}

type TrafficReply struct {
	Rx uint64
	Tx uint64
}