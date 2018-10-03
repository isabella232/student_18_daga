package daga

// TODO decide slice assign vs append, are we chasing that kind of performance +  ?

// TODO quick documentation and DAGA description with links to relevant parts of the Syta papers
// TODO see what to export and what not, for now everything private
import (
	"fmt"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/util/key"
	"hash"
)

// Suite represents the set of functionalities needed by the DAGA package
// (in other OOP terms it is kind of a DAGA interface, where we plug specific concrete DAGA implementations)
// to allow multiple implementations, (e.g one using EC crypto on edwards25519 curve and another using a Schnorr group like in DAGA paper)
// originally "DAGA assumes a cyclic multiplicative group G of prime order q, where p=2q+1,
// where the Discrete Logarithm and Decisional Diffie-Hellman assumptions hold" quoted from Syta - Identity Management Through Privacy Preserving Aut
//
// concrete suites are defined in daga/suite.go
type Suite interface {
	kyber.Group
	kyber.Random
	key.Generator // present since (e.g edwards25519) we need to take care while generating secrets, in order to avoid subgroup attacks
	kyber.HashFactory
	// TODO and maybe transform this suite concept/name into a daga interface and define methods needed by the algo to be implemented by the daga concrete implementations
	// => answer: no they (DEDIS) don't view Suite like that (even if Suites are really that fundamentally/ or compatible understanding)
	// FIXME "correct"/better names..
	hashTwo() hash.Hash  // DAGA needs another hash function of different size (TODO see if it is the case for all groups/concrete implementations and how to remain generic)
}

// EC crypto variant of DAGA Suite
var suite = newSuiteEC()  // FIXME remove and add suite parameter to all functions (oh looks likes a receiver for a daga concrete implementation ^^) its place is in "user" code for consistency with kyber code

/*AuthenticationContext holds all the constants of a particular DAGA authentication round.
The DAGA authentication context is established and published 'collectively' by the servers before an authentication round.
G contains the 'group' (<- poor choice of word) definition, that is the public keys of the clients (g.x) and the servers (g.y)
R contains the commitments of the servers to their unique per-round secrets
H contains the unique per-round generators of the clients*/
// TODO think of clever way to enforce/assert things like len(X)==len(H) (go-playground's validator ?)
// TODO maybe remove the g thing (ok we lose "compatibility with daga paper") and have a slice of a struct instead to enforce same length
type authenticationContext struct {
	g struct {
		x []kyber.Point
		y []kyber.Point
	}
	r []kyber.Point
	h []kyber.Point
}

/*AuthenticationMessage stores an authentication message request message sent by a client to an arbitrarily chosen server
c holds the AuthenticationContext used by the client to authenticate
s contains the client's commitments to the secrets shared with all the servers
t0 // TODO doc
p0 // TODO doc
*/
type authenticationMessage struct {
	c authenticationContext
	initialTagAndCommitments
	p0 clientProof
}

// TODO doc
type initialTagAndCommitments struct {
	sCommits  []kyber.Point // client's commitments to the shared secrets with the servers
	s 		kyber.Scalar	// product of all secrets that client shares with the servers
	t0 kyber.Point   // client's initial linkage tag
}

/*Client is used to store the client's key pair and index.*/
type client struct {
	key   key.Pair
	index int
}

/*NewClient is used to initialize a new client with a given index
If no private key is given, a random one is chosen
*/
// TODO see how this i will be handled...
func newClient(i int, s kyber.Scalar) (client, error) {
	if i < 0 {
		return client{}, fmt.Errorf("invalid parameters")
	}
	var kp *key.Pair
	if s == nil {
		kp = key.NewKeyPair(suite)
	} else {
		// FIXME check if s is a proper secret (see small subgroup attacks on some groups/curves)... or remove this option ..
		kp = &key.Pair{
			Private: s, // <- could (e.g. edwards25519) be attacked if not in proper form
			Public:  suite.Point().Mul(s, nil),
		}
	}
	return client{index: i, key: *kp}, nil
}

// FIXME better name + doc as of Syta - Identity Management Through Privacy Preserving Aut 4.3.5
// TODO parameter checking + logging
// TODO maybe split further into smaller methods, maybe one for each step
// TODO see if useful/idiomatic to create a struct or better to return "tuple"....
// #kyber daga
func newInitialTagAndCommitments(serverKeys []kyber.Point, clientGenerator kyber.Point) (initialTagAndCommitments, error) {
	//DAGA client Step 1: generate ephemeral DH key pair
	ephemeralKey := key.NewKeyPair(suite)
	z := ephemeralKey.Private
	Z := ephemeralKey.Public

	//DAGA client Step 2: generate shared secret exponents with the servers
	sharedSecrets := make([]kyber.Scalar, len(serverKeys))
	for _, serverKey := range serverKeys {
		// TODO ensure that this is working like I think its working..
		hasher := suite.Hash()
		// QUESTION ask Ewa Syta related hash question see log.txt (to my understanding secrets distribution will not be uniform and that kind of violate random oracle model assumption)
		// but since nothing is said about this concern in Curve25519 paper I'd say this is not an issue finally...
		// QUESTION unless it is specifically the purpose of the bit twiddling, ensure that the secret is in the correct subgroup of E see crypto thread https://crypto.stackexchange.com/questions/12425/why-are-the-lower-3-bits-of-curve25519-ed25519-secret-keys-cleared-during-creati
		// FIXME to my understanding we lose nothing (security-wise) by always performing the bittwiddlings and we might lose security if we don't !
		suite.Point().Mul(z, serverKey).MarshalTo(hasher)
		hash := hasher.Sum(nil)
		sharedSecret := suite.Scalar().SetBytes(hash)
		sharedSecrets = append(sharedSecrets, sharedSecret)
	}	//QUESTION don't understand why sha3(sha512) was done by previous student instead of sha256 in the first place...? => I use only one hash (sha256 for now)

	//DAGA client Step 3: computes initial linkage tag and commitments to the shared secrets
	//	Computes the value of the exponent for the initial linkage tag
	exp := suite.Scalar().One()
	for _, secret := range sharedSecrets {
		exp.Mul(exp, secret)
	}
	T0 := suite.Point().Mul(exp, clientGenerator)

	//	Computes the commitments to the shared secrets
	S := make([]kyber.Point, 0, len(serverKeys) + 2)
	S = append(S, Z, suite.Point().Base())
	exp = sharedSecrets[0]
	for _, sharedSecret := range sharedSecrets[1:] {
		S = append(S, suite.Point().Mul(exp, nil))
		exp.Mul(exp, sharedSecret)
	}
	S = append(S, suite.Point().Mul(exp, nil))
	return initialTagAndCommitments{t0: T0, sCommits: S, s: exp}, nil
}

/*CreateRequest generates the elements for the authentication request (T0, S) and the generation of the client's proof(s)*/
// TODO see if context big enough to transform it to *authenticationContext
// #"network"
func (c client) createRequest(context authenticationContext) (authenticationMessage, error) {
	// DAGA client Steps 1, 2, 3:
	ts, err := newInitialTagAndCommitments(context.g.y, context.h[c.index])
	if err != nil {
		// TODO log
		return authenticationMessage{}, err
	}

	// TODO server selection and circuit establishment + way to give circuit access to prove() see TODOs in prove()

	// DAGA client Step 4: sigma protocol / interactive proof of knowledge PK client, with one random server
	if P, err := prove(context, c, ts); err != nil { // TODO server communication not done
		// TODO log
		return authenticationMessage{}, err
	} else {
		M0 := authenticationMessage{
			c:                        context,
			initialTagAndCommitments: ts,
			p0:                       P,
		}
		return M0, nil
	}
}