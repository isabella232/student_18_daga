package daga_login

/*
This holds the messages used to communicate with the service over the network.
FIXME in fact no... they are in proto.go ... not sure how to keep kind of coherency with other cothority projects
=> put the methods here
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

// FIXME investigate if satori is still the package to use, saw claims that it should be deprecated in favor of newer forks
// ID of 3rd party service (that use DAGA as its auth. mechanism, don't confuse with Onet.ServiceID)
type ServiceID uuid.UUID
type ContextID uuid.UUID

// returns a pointer to newly allocated Context struct initialized with the provided daga.AuthenticationContext and roster
// (the returned context implement daga.AuthenticationContext interface too)
func NewContext(dagaContext daga.AuthenticationContext, roster *onet.Roster, serviceID ServiceID, signatures [][]byte) (*Context, error) {

	if err := daga.ValidateContext(dagaContext); err != nil {
		return nil, err
	} else {
		members := dagaContext.Members()
		return &Context{
			ContextID:                    ContextID(uuid.Must(uuid.NewV4())),
			ServiceID:                    serviceID,
			Signatures:                   signatures,
			X: members.X,
			Y: members.Y,
			R: dagaContext.ServersSecretsCommitments(),
			H: dagaContext.ClientsGenerators(),
			Roster:                       roster,
		}, nil
	}
}

// implement manually the daga.AuthenticationContext interface (to make awk happy with proto.go, previously and maybe later, daga.MinimumAuthenticationContext was/will be used)
// returns the context members (their public keys)
func (c Context) Members() daga.Members {
	return daga.Members{
		X: c.X,  // client/user keys
		Y: c.Y,  // server keys
	}
}

// implement manually the daga.AuthenticationContext interface (to make awk happy with proto.go, previously and maybe later, daga.MinimumAuthenticationContext was/will be used)
// returns the per round generators (one for each client/user)
func (c Context) ClientsGenerators() []kyber.Point {
	return c.H
}

// implement manually the daga.AuthenticationContext interface (to make awk happy with proto.go, previously and maybe later, daga.MinimumAuthenticationContext was/will be used)
// return the servers' commitments to their per-round secret
func (c Context) ServersSecretsCommitments() []kyber.Point {
	return c.R
}

// to be used by actors upon reception of request/reply to verify that it is part of same auth.context that was requested/is accepted.
// in general for DAGA to work we need to check/enforce same order but this function is only to check that the context is the "same"
// that one of our accepted context (TODO FIXME maybe not useful but maybe useful .. ).
// after the check done, to proceed remember to keep context that is in message/request/reply for all computations.
// FIXME compare IDs and basta, (maybe enforce strict equality by making context embed an hash of the fields that need to be strictly equal)
// and drop the idea that it might be useful to have "different-same" contexts (premature optimisation + dumb
// TODO (unless we consider having ~random group members assigned in unpredictable ways to mitigate the problem of context propagation and anonymity when new subscriber arrive and old leave)
// (different rosters => legitimate use to balance workload etc.. ??)
func (c Context) Equals(other Context) bool {
	// TODO consider moving this in kyber daga

	//if reflect.DeepEqual(c, other) {  // TODO check if it is useful... maybe can never work..
	//	return true
	//} else {
	members1 := c.Members()
	members2 := other.Members()
	return ContainsSameElems(members1.X, members2.X) &&
		ContainsSameElems(members1.Y, members2.Y) &&
		ContainsSameElems(c.ClientsGenerators(), other.ClientsGenerators()) &&
		ContainsSameElems(c.ServersSecretsCommitments(), other.ServersSecretsCommitments())
	//}
}

// used to translate a daga.Challenge to the "proto-awk" friendly version of it
func NetEncodeChallenge(challenge daga.Challenge) *PKclientChallenge {

	copyOfProofChallengeSigs := make([]ServerSignature, 0, len(challenge.Sigs))
	for _, dagaServerSig := range challenge.Sigs {
		copyOfProofChallengeSigs = append(copyOfProofChallengeSigs, ServerSignature{
			Index: dagaServerSig.Index,
			Sig: dagaServerSig.Sig,
		})
	}

	return &PKclientChallenge{
		Cs: challenge.Cs,
		Sigs: copyOfProofChallengeSigs,
	}
}

// used to translate back the "proto-awk" friendly version of a daga.Challenge
func (pkc PKclientChallenge) NetDecode() *daga.Challenge {

	copyOfProofChallengeSigs := make([]daga.ServerSignature, 0, len(pkc.Sigs))
	for _, serverSig := range pkc.Sigs {
		copyOfProofChallengeSigs = append(copyOfProofChallengeSigs, daga.ServerSignature{
			Index: serverSig.Index,
			Sig: serverSig.Sig,
		})
	}

	return &daga.Challenge{
		Cs:   pkc.Cs,
		Sigs: copyOfProofChallengeSigs,
	}
}

// used to translate a daga.AuthenticationMessage to the "net-and-proto-awk" friendly version of it
func NetEncodeAuthenticationMessage(context Context, msg daga.AuthenticationMessage) *Auth {

	// "deep-translate" proof
	copyOfProofChallenge := NetEncodeChallenge(msg.P0.Cs)

	copyOfProof := ClientProof{
		Cs: *copyOfProofChallenge,
		R: msg.P0.R,
		C: msg.P0.C,
		T: msg.P0.T,
	}

	return &Auth{
		Context:  context, // i.e. discard context part of message and use the one provided
		T0:       msg.T0,
		SCommits: msg.SCommits,
		Proof:    copyOfProof,
	}
}

// used to translate back the "net-and-proto-awk" friendly version of a daga.AuthenticationMessage
func (a Auth) NetDecode() (*daga.AuthenticationMessage, Context) {

	// "deep-translate" proof
	copyOfProofChallengeSigs := make([]daga.ServerSignature, 0, len(a.Proof.Cs.Sigs))
	for _, serverSig := range a.Proof.Cs.Sigs {
		copyOfProofChallengeSigs = append(copyOfProofChallengeSigs, daga.ServerSignature{
			Index: serverSig.Index,
			Sig: serverSig.Sig,
		})
	}

	copyOfProofChallenge := daga.Challenge{
		Cs: a.Proof.Cs.Cs,
		Sigs: copyOfProofChallengeSigs,
	}

	copyOfProof := daga.ClientProof{
		Cs: copyOfProofChallenge,
		R: a.Proof.R,
		C: a.Proof.C,
		T: a.Proof.T,
	}

	msg := daga.AuthenticationMessage{
		C:  a.Context,
		P0: copyOfProof,
	}
	msg.SCommits = a.SCommits
	msg.T0 = a.T0
	return &msg, a.Context
}

// used to translate a daga.ServerMessage to the "net-and-proto-awk" friendly version of it
func NetEncodeServerMessage(context Context, msg *daga.ServerMessage) *AuthReply {
	request := NetEncodeAuthenticationMessage(context, msg.Request)

	// "translate" sigs
	copyOfSigs := make([]ServerSignature, 0, len(msg.Sigs))
	for _, dagaServerSig := range msg.Sigs {
		copyOfSigs = append(copyOfSigs, ServerSignature{
			Index: dagaServerSig.Index,
			Sig: dagaServerSig.Sig,
		})
	}

	// "translate" proofs
	copyOfServerProofs := make([]ServerProof, 0, len(msg.Proofs))
	for _, dagaServerProof := range msg.Proofs {
		copyOfServerProofs = append(copyOfServerProofs, ServerProof{
			C: dagaServerProof.C,
			R1: dagaServerProof.R1,
			R2: dagaServerProof.R2,
			T1: dagaServerProof.T1,
			T2: dagaServerProof.T2,
			T3: dagaServerProof.T3,
		})
	}

	return &AuthReply{
		Request: *request,
		Sigs:    copyOfSigs,
		Proofs:  copyOfServerProofs,
		Tags:    msg.Tags,
		Indexes: msg.Indexes,
	}
}

// used to translate back the "net-and-proto-awk" friendly version of a daga.NetServerMessage
func (ar AuthReply) NetDecode() (*daga.ServerMessage, Context) {
	request, context := ar.Request.NetDecode()

	// "translate" sigs
	copyOfSigs := make([]daga.ServerSignature, 0, len(ar.Sigs))
	for _, serverSig := range ar.Sigs {
		copyOfSigs = append(copyOfSigs, daga.ServerSignature{
			Index: serverSig.Index,
			Sig: serverSig.Sig,
		})
	}

	// "translate" proofs
	copyOfServerProofs := make([]daga.ServerProof, 0, len(ar.Proofs))
	for _, serverProof := range ar.Proofs {
		copyOfServerProofs = append(copyOfServerProofs, daga.ServerProof{
			C: serverProof.C,
			R1: serverProof.R1,
			R2: serverProof.R2,
			T1: serverProof.T1,
			T2: serverProof.T2,
			T3: serverProof.T3,
		})
	}

	return &daga.ServerMessage{
		Request: *request,
		Tags:    ar.Tags,
		Proofs:  copyOfServerProofs,
		Sigs:    copyOfSigs,
		Indexes: ar.Indexes,
	}, context
}