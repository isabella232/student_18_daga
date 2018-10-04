package daga

// TODO decide slice assign vs append, are we chasing that kind of performance +  ?
// TODO decide / review method vs functions + "granularity of parameters"

// TODO quick documentation and DAGA description with links to relevant parts of the Syta papers
// TODO see what to export and what not, for now everything private
import (
	"errors"
	"fmt"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/sign/schnorr"
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
var suite = NewSuiteEC()  // FIXME remove and add suite parameter to all functions (oh looks likes a receiver for a daga concrete implementation ^^) its place is in "user" code for consistency with kyber code

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

func NewAuthenticationContext(x, y, r, h []kyber.Point) (*authenticationContext, error) {
	if (len(x) != len(h) || len(y) != len(r) || len(x) == 0 || len(y) == 0) {
		return nil, errors.New("NewAuthenticationContext: illegal length, len(x) != len(h) Or len(y) != len(r) Or zero length slices")
	}
	return &authenticationContext{
		g: struct {
			x []kyber.Point
			y []kyber.Point
		}{
			x:x,
			y:y,
		},
		r:r,
		h:h,
	}, nil
}

func (ac authenticationContext) Members() (X, Y []kyber.Point) {
	return ac.g.x, ac.g.y
}

/*AuthenticationMessage stores an authentication message request message sent by a client to an arbitrarily chosen server
c holds the AuthenticationContext used by the client to authenticate
s contains the client's commitments to the secrets shared with all the servers
t0 // TODO doc
p0 // TODO doc
*/
type authenticationMessage struct {
	c authenticationContext
	initialTagAndCommitments  // FIXME hahah I currently send the secrets
	p0 clientProof
}

// TODO doc
type initialTagAndCommitments struct {
	sCommits  []kyber.Point // client's commitments to the shared secrets with the servers
	t0 kyber.Point   // client's initial linkage tag
}

/*Client is used to store the client's key pair and index.*/
type Client struct {
	key   key.Pair
	index int
}

/*NewClient is used to initialize a new client with a given index
If no private key is given, a random one is chosen
*/
// TODO see how this i will be handled...
func NewClient(i int, s kyber.Scalar) (*Client, error) {
	if i < 0 {
		return nil, fmt.Errorf("invalid parameters")
	}

	var kp *key.Pair
	if s == nil {
		kp = key.NewKeyPair(suite)
	} else {
		// FIXME check if s is a proper secret (see small subgroup attacks on some groups/curves)... or remove this option ..or make it a proper secret..
		kp = &key.Pair{
			Private: s, // <- could (e.g. edwards25519) be attacked if not in proper form
			Public:  suite.Point().Mul(s, nil),
		}
	}

	return &Client{
		index: i,
		key: *kp,
	}, nil
}

// FIXME better name + doc as of Syta - Identity Management Through Privacy Preserving Aut 4.3.5
// TODO parameter checking + logging
// TODO maybe split further into smaller methods, maybe one for each step
// TODO see if useful/idiomatic to create a struct or better to return "tuple"....
//s 		kyber.Scalar	// product of all secrets that client shares with the servers
// #kyber daga
func newInitialTagAndCommitments(serverKeys []kyber.Point, clientGenerator kyber.Point) (*initialTagAndCommitments, kyber.Scalar, error) {
	//DAGA client Step 1: generate ephemeral DH key pair
	ephemeralKey := key.NewKeyPair(suite)
	z := ephemeralKey.Private
	Z := ephemeralKey.Public

	//DAGA client Step 2: generate shared secret exponents with the servers
	sharedSecrets := make([]kyber.Scalar, 0, len(serverKeys))
	for _, serverKey := range serverKeys {
		// TODO ensure that this is working like I think its working..
		hasher := suite.Hash()
		// QUESTION ask Ewa Syta related hash question see log.txt (to my understanding secrets distribution will not be uniform and that kind of violate random oracle model assumption)
		// but since nothing is said about this concern in Curve25519 paper I'd say this is not an issue finally...
		// QUESTION unless it is specifically the purpose of the bit twiddling, ensure that the secret is in the correct subgroup of E see crypto thread https://crypto.stackexchange.com/questions/12425/why-are-the-lower-3-bits-of-curve25519-ed25519-secret-keys-cleared-during-creati
		suite.Point().Mul(z, serverKey).MarshalTo(hasher)
		hash := hasher.Sum(nil)
		sharedSecret := suite.Scalar().SetBytes(hash)
		// FIXME tweak the bits, to my understanding we lose nothing (security-wise) by always performing the bittwiddlings and we might lose security if we don't !
		sharedSecrets = append(sharedSecrets, sharedSecret)
	}	// QUESTION don't understand why sha3(sha512) was done by previous student instead of sha256 in the first place...? => I use only one hash (sha256 for now)

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
	s := exp

	return &initialTagAndCommitments{
		t0: T0,
		sCommits: S,
	}, s, nil
}

func (c Client)  PublicKey() kyber.Point {
	return c.key.Public
}

// TODO doc, see if context big enough to transform it to *authenticationContext
// #"network"
func (c Client) NewAuthenticationMessage(context authenticationContext) (*authenticationMessage, error) {
	// DAGA client Steps 1, 2, 3:
	ts, s, err := newInitialTagAndCommitments(context.g.y, context.h[c.index])
	if err != nil {
		// TODO log
		return nil, err
	}

	// QUESTION can I have a quick intro on how I to do this using onet ? or should I do my own cuisine ?
	// QUESTION TODO FIXME, will need to have kind of a directory mapping servers to their IP/location don't currently know how this is addressed in cothority onet
	// TODO server selection and circuit establishment
	// TODO + way to give circuit access to newClientProof(), for now channels
	// TODO pick random server and find its location
	// TODO establish anon circuit/channel from/to server
	// TODO code to encode/decode data
	// TODO using the "function that returns channels" pattern
	var pushCommitments chan []kyber.Point
	var pullChallenge chan kyber.Scalar

	// DAGA client Step 4: sigma protocol / interactive proof of knowledge PK client, with one random server
	if P, err := newClientProof(context, c, *ts, s, pushCommitments, pullChallenge); err != nil {
		// TODO log
		return nil, err
	} else {
		M0 := authenticationMessage{
			c:                        context,
			initialTagAndCommitments: *ts,
			p0:                       P,
		}
		return &M0, nil
	}
}











// FIXME clean those below when tests passes
/*ECDSASign gnerates a Schnorr signature*/
// QUESTION another WTF, why bring ECDSA here ? but ok keep for now .. => move to eddsa
func ECDSASign(priv kyber.Scalar, msg []byte) (s []byte, err error) {
	//Input checks
	if priv == nil {
		return nil, fmt.Errorf("Empty private key")
	}
	if msg == nil || len(msg) == 0 {
		return nil, fmt.Errorf("Empty message")
	}

	s, err = schnorr.Sign(suite, priv, msg)
	if err != nil {
		return nil, fmt.Errorf("Error in the signature generation")
	}
	return s, nil
}

/*ECDSAVerify checks if a Schnorr signature is valid*/
// QUESTION same WTF as above
func ECDSAVerify(public kyber.Point, msg, sig []byte) (err error) {
	//Input checks
	if public == nil {
		return fmt.Errorf("Empty public key")
	}
	if msg == nil || len(msg) == 0 {
		return fmt.Errorf("Empty message")
	}
	if sig == nil || len(sig) == 0 {
		return fmt.Errorf("Empty signature")
	}

	err = schnorr.Verify(suite, public, msg, sig)
	return err
}

/*ToBytes is a utility functton to convert a ContextEd25519 into []byte, used in signatures*/
// QUESTION WTF ?
func (context *authenticationContext) ToBytes() (data []byte, err error) {
	temp, e := PointArrayToBytes(&context.g.x)
	if e != nil {
		return nil, fmt.Errorf("Error in X: %s", e)
	}
	data = append(data, temp...)

	temp, e = PointArrayToBytes(&context.g.y)
	if e != nil {
		return nil, fmt.Errorf("Error in Y: %s", e)
	}
	data = append(data, temp...)

	temp, e = PointArrayToBytes(&context.h)
	if e != nil {
		return nil, fmt.Errorf("Error in H: %s", e)
	}
	data = append(data, temp...)

	temp, e = PointArrayToBytes(&context.r)
	if e != nil {
		return nil, fmt.Errorf("Error in R: %s", e)
	}
	data = append(data, temp...)

	return data, nil
}

/*PointArrayToBytes is a utility function to convert a kyber.Point array into []byte, used in signatures*/
// QUESTION same as above
func PointArrayToBytes(array *[]kyber.Point) (data []byte, err error) {
	for _, p := range *array {
		temp, e := p.MarshalBinary()
		if e != nil {
			return nil, fmt.Errorf("Error in S: %s", e)
		}
		data = append(data, temp...)
	}
	return data, nil
}

/*ScalarArrayToBytes is a utility function to convert a kyber.Scalar array into []byte, used in signatures*/
// QUESTION same as above
func ScalarArrayToBytes(array *[]kyber.Scalar) (data []byte, err error) {
	for _, s := range *array {
		temp, e := s.MarshalBinary()
		if e != nil {
			return nil, fmt.Errorf("Error in S: %s", e)
		}
		data = append(data, temp...)
	}
	return data, nil
}


