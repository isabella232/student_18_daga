package daga_login

/*
This holds the messages used to communicate with the service over the network.
FIXME in fact no... they are in proto.go ... not sure how to keep kind of coherency with other cothority projects
=> put the methods here
*/

import (
	"fmt"
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

func NetEncodeAuthenticationMessage(context Context, msg daga.AuthenticationMessage) *NetAuthenticationMessage {
	return &NetAuthenticationMessage{
		Context:  context, // i.e. discard context part of message and use the one provided
		T0:       msg.T0,
		SCommits: msg.SCommits,
		Proof:    msg.P0,
	}
}

func (netmsg NetAuthenticationMessage) NetDecode() (*daga.AuthenticationMessage, Context, error) {
	msg := daga.AuthenticationMessage{
		C:  netmsg.Context.MinimumAuthenticationContext,
		P0: netmsg.Proof,
	}
	msg.SCommits = netmsg.SCommits
	msg.T0 = netmsg.T0
	return &msg, netmsg.Context, nil
}

func NetEncodeServerMessage(context Context, msg *daga.ServerMessage) *NetServerMessage {
	request := NetEncodeAuthenticationMessage(context, msg.Request)
	return &NetServerMessage{
		Request: *request,
		Sigs:    msg.Sigs,
		Proofs:  msg.Proofs,
		Tags:    msg.Tags,
		Indexes: msg.Indexes,
	}
}

func (netmsg NetServerMessage) NetDecode() (*daga.ServerMessage, Context, error) {
	request, context, err := netmsg.Request.NetDecode()
	if err != nil {
		return nil, Context{}, fmt.Errorf("failed to decode request: %s", err)
	}
	return &daga.ServerMessage{
		Request: *request,
		Tags:    netmsg.Tags,
		Proofs:  netmsg.Proofs,
		Sigs:    netmsg.Sigs,
		Indexes: netmsg.Indexes,
	}, context, nil
}