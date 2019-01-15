// TODO quick documentation and DAGA description with links to relevant parts of the Syta papers and or my report
//  (or cp paste of relevant part of my report)
//  + note about IMHO package has nothing to do with signatures but ...,
package daga

// TODO decide / review method vs functions + "granularity of parameters"
//  I'd say put DAGA "primitives" as functions and create methods on clients and servers that use those,
//  put the daga primitives into kyber and the rest into a DAGA package somewhere else in cothority
import (
	"errors"
	"fmt"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/sign/schnorr"
	"github.com/dedis/kyber/util/key"
	"hash"
)

// Suite represents the set of functionalities needed for the DAGA package to operate
// the purpose of the Suite is to allow multiple implementations using different cryptographic primitives,
// e.g an implementation using EC crypto on edwards25519 curve and another one using a Schnorr group like in the original DAGA paper,
// (originally "DAGA assumes a cyclic multiplicative group G of prime order q, where p=2q+1,
// where the Discrete Logarithm and Decisional Diffie-Hellman assumptions hold"
// quoted from Syta - Identity Management Through Privacy Preserving Aut)
//
// concrete suites are defined in daga/suite.go
// TODO daga.Suite idea is a good idea but probably a bad idea too, since it wasn't introduced from start
//  we should choose a group and make sure everything works well
//  together and with group.. or push it to the extremes and use it correctly (but lots of crypto details to look..)
//  ==> do it when rewriting server part.
type Suite interface {
	kyber.Group
	kyber.Random
	key.Generator     // needed since sometimes/in some groups we need to take care while generating secrets, (e.g in edwards25519, to avoid small subgroup attacks, need to mask some bits to make all secrets multiple of 8)
	kyber.HashFactory  // to map input to non trivial scalars (i.e. in Zq* for the Schnorr group example)
	// TODO remove this hashfactory and defines hash1 hash2 as hash functions that should behaves like RO and that map input to scalars and field elements respectively
	//  and / or eventually keep hashfactory for the usage that don't care and specify which hash is used.
	//  see too the comment on SchnorSign => better to have signing related things a requirement in the suite
	hashTwo() hash.Hash // DAGA needs another hash function to map input to field elements (i.e. Zp for the schnorr group example) (that can be of another size depending on the concrete groups used)
}

// AuthenticationContext holds all the constants of a particular DAGA authentication round.
//
// In DAGA "we define an authentication round with respect to a particular authentication
// context C. Each authentication request, regardless of the identity of the originating
// client, belongs to the same round if it is made with respect to C. All requests within
// the same round are linkable, that is, each time a client i authenticates, the servers
// will be able to link these requests as coming from some client from" the group.
//
// The DAGA authentication context is established and published 'collectively' by the servers before an authentication round.
// An authentication context might be one time, where each client is expected to make exactly one authentication request
// or a context may remain valid for certain period of time or some maximum number of
// authentications made by a single clients or all of clients in g.x. Since the servers can
// keep track of each anonymous client’s authentication request, a client may be allowed
// to make up to k requests so that each request beyond that is rejected regardless of the
// validity of the supplied authentication message. After a context expires, all servers
// securely erase their per-round secrets r making it impossible to process authentication
// messages within this context.
// See "Syta - Identity Management Through Privacy Preserving Aut Chapter 4.7.3"
type AuthenticationContext interface {
	Members() Members
	ClientsGenerators() []kyber.Point
	ServersSecretsCommitments() []kyber.Point
}

// the members of an auth. context
//
// X the public keys of the clients/users/entities
//
// Y the public keys of the servers
type Members struct {
	X, Y []kyber.Point
}

// minimum DAGA context, containing nothing but what DAGA needs to work internally
// used for the test suite and in context factories
// (or later in concrete contexts, as a way to implement for you the interface) (if you don't need to generate proto files in your new project......)
//
// G contains the 'group' (see "Syta - Identity Management Through Privacy Preserving Aut Chapter 2.3" for terminology) definition,
// that is the public keys of the clients (G.X) and the servers (G.Y)
//
// R contains the commitments of the servers to their unique per-round secrets
//
// H contains the unique per-round generators of the group (<- the algebraic structure) associated to each clients
// TODO maybe remove the G thing (but we lose reading "compatibility with daga paper")
//  and instead have a slices of struct {x, h} and struct {y, r} to enforce same length
type MinimumAuthenticationContext struct {
	G Members
	R []kyber.Point
	H []kyber.Point
}

// returns a pointer to a newly allocated MinimumAuthenticationContext initialized with :
//
// x the public keys of the clients
//
// y the public keys of the servers
//
// r the commitments of the servers to their unique per-round secrets
//
// h the unique per-round generators of the group associated to each clients
func NewMinimumAuthenticationContext(x, y, r, h []kyber.Point) (*MinimumAuthenticationContext, error) {
	context := MinimumAuthenticationContext{
		G: Members{
			X: x,
			Y: y,
		},
		R: r,
		H: h,
	}
	if err := ValidateContext(context); err != nil {
		return nil, err
	} else {
		return &context, nil
	}
}

// Members returns the public keys of the members of an AuthenticationContext, client keys in X and server keys in Y
func (ac MinimumAuthenticationContext) Members() Members {
	return ac.G
}

// ClientsGenerators returns the per-round generator of the clients for this AuthenticationContext
func (ac MinimumAuthenticationContext) ClientsGenerators() []kyber.Point {
	return ac.H
}

func (ac MinimumAuthenticationContext) ServersSecretsCommitments() []kyber.Point {
	return ac.R
}

func ValidateContext(context AuthenticationContext) error {
	members := context.Members()
	// TODO maybe other thing, notably on generators,
	//  (points/keys don't have small order, or i.e. generators are generators of the correct subgroup etc..)
	//  see the related questions in client.go, resolve "issues" related to context management when context evolution implemented in dagacothority and
	//  then decide/fix sign/daga server and context related code/API and rewrite them.
	//  (now in cothority service implementation a node won't serve auth. requests under a context it didn't built and approve => + anytrust we are ok)
	if len(members.X) != len(context.ClientsGenerators()) || len(members.Y) != len(context.ServersSecretsCommitments()) || len(members.X) == 0 || len(members.Y) == 0 {
		return errors.New("ValidateContext: illegal length, len(x) != len(h) Or len(y) != len(r) Or zero length slices")
	}
	return nil
}

// Signs using schnorr signature scheme over the group of the Suite
//  QUESTION easy to confuse what are the exact properties of the sign algo here, (e.g. more like ecdsa or eddsa ?), lacks documentation,
//   how to interop with other existing implementations out there etc.. (not our concern for now but.) ?
//   + maybe put it in suite and move implementation in suiteEC (or maybe design a kyber signer interface that offer sign/verify/newkey etc..)
func SchnorrSign(suite Suite, private kyber.Scalar, msg []byte) (s []byte, err error) {
	//Input checks
	if private == nil {
		return nil, errors.New("cannot sign, no private key provided")
	}
	if len(msg) == 0 {
		return nil, errors.New("empty message")
	}

	s, err = schnorr.Sign(suite, private, msg)
	if err != nil {
		return nil, errors.New("failed to sign the message: " + err.Error())
	}
	return s, nil
}

// SchnorrVerify checks if a Schnorr signature generated using SchnorrSign is valid and returns an error if it is not the case
// QUESTION same as above
func SchnorrVerify(suite Suite, public kyber.Point, msg, sig []byte) (err error) {
	//Input checks
	if public == nil {
		return fmt.Errorf("cannot verify, no public key provided")
	}
	if len(msg) == 0 {
		return fmt.Errorf("empty message")
	}
	if len(sig) == 0 {
		return fmt.Errorf("empty signature")
	}

	err = schnorr.Verify(suite, public, msg, sig)
	return err
}

//AuthenticationContextToBytes is a utility function that marshal a context into []byte, used in signatures
func AuthenticationContextToBytes(ac AuthenticationContext) (data []byte, err error) {
	members := ac.Members()
	temp, e := PointArrayToBytes(members.X)
	if e != nil {
		return nil, fmt.Errorf("AuthenticationContextToBytes: error marshaling X: %s", e)
	}
	data = append(data, temp...)

	temp, e = PointArrayToBytes(members.Y)
	if e != nil {
		return nil, fmt.Errorf("AuthenticationContextToBytes: error marshaling Y: %s", e)
	}
	data = append(data, temp...)

	temp, e = PointArrayToBytes(ac.ClientsGenerators())
	if e != nil {
		return nil, fmt.Errorf("AuthenticationContextToBytes: error marshaling H: %s", e)
	}
	data = append(data, temp...)

	temp, e = PointArrayToBytes(ac.ServersSecretsCommitments())
	if e != nil {
		return nil, fmt.Errorf("AuthenticationContextToBytes: error marshaling R: %s", e)
	}
	data = append(data, temp...)

	return data, nil
}

//PointArrayToBytes is a utility function that marshal a kyber.Point array into []byte, used in signatures
func PointArrayToBytes(array []kyber.Point) (data []byte, err error) {
	for _, p := range array {
		temp, e := p.MarshalBinary() // hope p not nil..
		if e != nil {
			return nil, e
		}
		data = append(data, temp...)
	}
	return data, nil
}

//ScalarArrayToBytes is a utility function that marshal a kyber.Scalar array into []byte, used in signatures
func ScalarArrayToBytes(array []kyber.Scalar) (data []byte, err error) {
	for _, s := range array {
		temp, e := s.MarshalBinary()
		if e != nil {
			return nil, e
		}
		data = append(data, temp...)
	}
	return data, nil
}

//ToBytes is a helper function that marshal a ClientMessage into []byte to be used in signatures
func (msg AuthenticationMessage) ToBytes() (data []byte, err error) {
	data, e := AuthenticationContextToBytes(msg.C)
	if e != nil {
		return nil, fmt.Errorf("error in context: %s", e)
	}

	temp, e := PointArrayToBytes(msg.SCommits)
	if e != nil {
		return nil, fmt.Errorf("error in S: %s", e)
	}
	data = append(data, temp...)

	temp, e = msg.T0.MarshalBinary()
	if e != nil {
		return nil, fmt.Errorf("error in T0: %s", e)
	}
	data = append(data, temp...)

	temp, e = msg.P0.ToBytes()
	if e != nil {
		return nil, fmt.Errorf("error in proof: %s", e)
	}
	data = append(data, temp...)

	return data, nil
}
