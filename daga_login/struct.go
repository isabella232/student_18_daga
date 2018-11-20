package daga_login

/*
This holds the messages used to communicate with the service over the network.
*/

import (
	"github.com/dedis/kyber"
	"github.com/dedis/onet"
	"github.com/dedis/onet/network"
	"github.com/dedis/student_18_daga/sign/daga"
	"github.com/satori/go.uuid"
)

// register all API messages s.t. the network knows how to handle/marshal/unmarshal them.
func init() {
	network.RegisterMessages(
		PKclientCommitments{}, PKclientChallenge{},
		Auth{}, AuthReply{},
	)
}

// QUESTION ?
const (
	// ErrorParse indicates an error while parsing the protobuf-file.
	ErrorParse = iota + 4000
)

// CreateContext will initiate the context generation protocol that will result in a CreateContextReply
type CreateContext struct {
	ServiceID       ServiceID // used to identify 3rd-party service making the request (maybe we don't need to strictly identify but easier for now, later can rely on other schemes)
	Signature       []byte    // used to authenticate 3rd-party service admin  (chicken-egg problem, we need to authenticate these requests, cannot accept every request..)
	SubscribersKeys []kyber.Point
	// TODO replace with ID of PoP instance later (IMHO DAGA should only be concerned with keys, no how the service gather them but Linus prefer other way around => maybe offer both ways)
	// (it is the service's business to get the keys of its subscriber => can use a PoP party, can just ask for keys etc..)
	// TODO FIXME + remember that DAGA expect Keys from the daga.Suite in use (=> maybe different from the PoP party => to be correct/general/etc.. would need KDFs)
	DagaNodes *onet.Roster // all the nodes that the 3rd-party service wants to include in its DAGA cothority
}

type CreateContextReply struct {
	Context Context
	// TODO replace with ID of byzcoin instance later (but IMHO DAGA should not be concerned in how the service distribute / publish context => can use bizcoin to manage its own state but this is different from forcing every users(clients or services) to use byzcoin to retrieve context)
}

// PKclientCommitments will initiate the challenge generation protocol that will result in a PKclientChallenge
type PKclientCommitments struct {
	Context     Context // to early reject auth requests part of context that the server doesn't care about
	Commitments []kyber.Point
}
type PKclientChallenge daga.Challenge

// Auth will start the authentication of client that will result (on success) in an AuthReply
type Auth NetAuthenticationMessage
type AuthReply NetServerMessage // FIXME don't reply with server message and fix the dumbness in daga.server..

// FIXME investigate if satori is still the package to use, saw claims that it should be deprecated in favor of newer forks
type ServiceID uuid.UUID // ID of 3rd party service (that use DAGA as its auth. mechanism, don't confuse with Onet.ServiceID)
type ContextID uuid.UUID

// Context implements the daga.AuthenticationContext interface
// and embed a corresponding Onet roster (how to reach the DAGA servers)
type Context struct {
	ID         ContextID
	ServiceID  ServiceID // ID of the 3rd-party service that use this context for auth. purposes
	Signatures [][]byte  // signatures that show endorsement of the context by all the daga servers
	daga.MinimumAuthenticationContext
	*onet.Roster
}

// returns a pointer to newly allocated Context struct initialized with the provided daga.AuthenticationContext and roster
func NewContext(dagaContext daga.AuthenticationContext, roster *onet.Roster, serviceID ServiceID, signatures [][]byte) (*Context, error) {

	// TODO or instead create and export a daga function that validate context components
	// recreate a daga context (and verify that the provided context is valid)
	X, Y := dagaContext.Members()
	newDagaContext, err := daga.NewMinimumAuthenticationContext(X, Y, dagaContext.ServersSecretsCommitments(), dagaContext.ClientsGenerators())
	if err != nil {
		return nil, err
	}
	return &Context{
		ID:                           ContextID(uuid.Must(uuid.NewV4())),
		ServiceID:                    serviceID,
		Signatures:                   signatures,
		MinimumAuthenticationContext: *newDagaContext,
		Roster:                       roster,
	}, nil
}

// to be used by actors upon reception of request/reply to verify that it is part of same auth.context that was requested/is accepted.
// in general for DAGA to work we need to check/enforce same order but this function is only to check that the context is the "same"
// that one of our accepted context (TODO FIXME maybe not useful but maybe useful .. ).
// after the check done, to proceed remember to keep context that is in message/request/reply for all computations.
// FIXME compare IDs and basta, (maybe enforce strict equality by making context embed an hash of the fields that need to be strictly equal)
// and drop the idea that it might be useful to have "different-same" contexts (premature optimisation + dumb (unless we consider having ~random group members assigned in unpredictable ways to mitigate the problem of context propagation and anonymity when new subscriber arrive and old leave)
// (different rosters => legitimate use to balance workload etc.. ??)
func (c Context) Equals(other Context) bool {
	// TODO consider moving this in kyber daga

	//if reflect.DeepEqual(c, other) {  // TODO check if it is useful... maybe can never work..
	//	return true
	//} else {
	X1, Y1 := c.Members()
	X2, Y2 := other.Members()
	return ContainsSameElems(X1, X2) &&
		ContainsSameElems(Y1, Y2) &&
		ContainsSameElems(c.ClientsGenerators(), other.ClientsGenerators()) &&
		ContainsSameElems(c.ServersSecretsCommitments(), other.ServersSecretsCommitments())
	//}
}

func (c Context) ServerIndexOf(publicKey kyber.Point) (int, error) {
	_, Y := c.Members()
	return IndexOf(Y, publicKey)
}
