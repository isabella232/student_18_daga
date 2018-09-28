package daga

// TODO quick documentation and DAGA description with links to relevant parts of the Syta papers
// TODO see what to export and what not
// QUESTION ask if append should be replaced by assign if possible (are we chasing that kind of performance ?)

import (
	"fmt"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/proof"
	"github.com/dedis/kyber/util/key"
	"hash"
	"strconv"
)

// Suite represents the set of functionalities needed by the DAGA package
// to allow multiple implementations, (e.g one using EC crypto on edwards25519 curve and another using a Schnorr group like in DAGA paper)
// originally "DAGA assumes a cyclic multiplicative group G of prime order q, where p=2q+1,
// where the Discrete Logarithm and Decisional Diffie-Hellman assumptions hold" quoted from Syta - Identity Management Through Privacy Preserving Aut
//
// concrete suites are defined in daga/suite.go
type Suite interface {
	kyber.Group
	kyber.Random
	//QUESTION use key.Generator interface instead ?
	newKey() kyber.Scalar // present since in the case of edwards25519 we need to take care in order to avoid subgroup attacks
	hashOne() hash.Hash   // FIXME "correct" names..and maybe transform this suite concept into a daga interface and define methods needed by the algo
	hashTwo() hash.Hash
}

// EC crypto variant of DAGA Suite
var suite = newSuiteEC()

/*AuthenticationContext holds all the constants of a particular DAGA authentication round.
The DAGA authentication context is established and published 'collectively' by the servers before an authentication round.
G contains the 'group' (<- poor choice of word) definition, that is the public keys of the clients (g.x) and the servers (g.y)
R contains the commitments of the servers to their unique per-round secrets
H contains the unique per-round generators of the clients*/
// TODO think of clever way to enforce/assert things like len(X)==len(H) (go-playground's validator ?)
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
t0 // TODO
p0 // TODO
*/
type authenticationMessage struct {
	c authenticationContext
	initialTagAndCommitments
	p0 clientProof
}

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
func NewClient(i int, s kyber.Scalar) (client, error) {
	if i < 0 {
		return client{}, fmt.Errorf("invalid parameters")
	}
	var kp *key.Pair
	if s == nil {
		kp = key.NewKeyPair(suite)
	} else {
		kp = &key.Pair{
			Private: s,
			Public:  suite.Point().Mul(s, nil),
		}
	}
	return client{index: i, key: *kp}, nil
}

// FIXME better name + doc as of Syta - Identity Management Through Privacy Preserving Aut 4.3.5
// TODO see if not better to replace parameters by serverkeys and clientgenerator (only useful things) => that's what I'v done
// TODO parameter checking + logging
// TODO maybe split further into smaller methods, maybe one for each step
// TODO see if useful to create a struct or better to return "tuple"....
// #kyber daga
func newInitialTagAndCommitments(serverKeys []kyber.Point, clientGenerator kyber.Point) (initialTagAndCommitments, error) {
	//func newInitialTagAndCommitments(context authenticationContext, clientIndex int) (*initialTagAndCommitments, error) {
	//DAGA client Step 1: generate ephemeral DH key pair
	ephemeralKey := key.NewKeyPair(suite)
	z := ephemeralKey.Private
	Z := ephemeralKey.Public

	//DAGA client Step 2: generate shared secret exponents with the servers
	sharedSecrets := make([]kyber.Scalar, 0, len(serverKeys))
	for _, serverKey := range serverKeys {
		// TODO ensure that this is working like I think its working..
		hasher := suite.hashOne()
		// QUESTION FIXME do we need to ensure that the unlikely 00000 hash never occurs or something else ? (I'd say yes)
		// QUESTION ask related hash question see log.txt (to my understanding secrets distribution will not be uniform and that kind of violate random oracle model assumption)
		_, err := suite.Point().Mul(z, serverKey).MarshalTo(hasher)
		if err != nil {
			// FIXME never happens or ??
			return initialTagAndCommitments{}, fmt.Errorf("error generating shared secrets: %s", err)
		}
		hash := hasher.Sum(nil)
		sharedSecret := suite.Scalar().SetBytes(hash)
		sharedSecrets = append(sharedSecrets, sharedSecret)
	}

	//DAGA client Step 3: computes initial linkage tag and commitments to the shared secrets
	//	Computes the value of the exponent for the initial linkage tag
	exp := suite.Scalar().One()
	for _, secret := range sharedSecrets {
		exp.Mul(exp, secret)
	}
	//QUESTION don't understand why sha3(sha512) was done by previous student instead of sha256 in the first place...? => can I rewrite everything since this is what I'm doing anywhay..)
	T0 := suite.Point().Mul(exp, clientGenerator)

	//	Computes the commitments to the shared secrets
	S := make([]kyber.Point, 0, len(serverKeys)+2)
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
		// TODO onet.log something
	}

	// DAGA client Step 4: sigma protocol / interactive proof of knowledge PK client, with one server
	//	construct the Prover for PK client
	prover := newClientProver(context, c, ts)
	//	3-move interaction with server picked at random
	// QUESTION TODO FIXME, will need to have kind of a directory mapping servers to their IP/location don't currently know how this is addressed in cothority onet
	prov

	M0 := authenticationMessage{
		c:                        context,
		initialTagAndCommitments: ts,
		p0:                       P,
	}

	return M0, nil
}












































/*ECDSASign generates a Schnorr signature*/
// TODO see if make sense to keep it since schnorr sign is part of kyber.
// TODO maybe to enforce/assert some properties on the signature => need to read more DAGA paper
// TODO for now comment out
//func ECDSASign(priv kyber.Scalar, msg []byte) (s []byte, err error) {
//	//Input checks
//	if priv == nil {
//		return nil, fmt.Errorf("Empty private key")
//	}
//	if msg == nil || len(msg) == 0 {
//		return nil, fmt.Errorf("Empty message")
//	}
//
//	s, err = Schnorr(suite, priv, msg)
//	if err != nil {
//		return nil, fmt.Errorf("Error in the signature generation")
//	}
//	return s, nil
//}

/*ECDSAVerify checks if a Schnorr signature is valid*/
// TODO same concerns as above
//func ECDSAVerify(public kyber.Point, msg, sig []byte) (err error) {
//	//Input checks
//	if public == nil {
//		return fmt.Errorf("Empty public key")
//	}
//	if msg == nil || len(msg) == 0 {
//		return fmt.Errorf("Empty message")
//	}
//	if sig == nil || len(sig) == 0 {
//		return fmt.Errorf("Empty signature")
//	}
//
//	err = sign.VerifySchnorr(suite, public, msg, sig)
//	return err
//}

// TODO see later but for now I don't see the point and it is not DRY enough for me
///*ToBytes is a utility functton to convert a ContextEd25519 into []byte, used in signatures*/
//func (context *ContextEd25519) ToBytes() (data []byte, err error) {
//	temp, e := PointArrayToBytes(&context.G.X)
//	if e != nil {
//		return nil, fmt.Errorf("Error in X: %s", e)
//	}
//	data = append(data, temp...)
//
//	temp, e = PointArrayToBytes(&context.G.Y)
//	if e != nil {
//		return nil, fmt.Errorf("Error in Y: %s", e)
//	}
//	data = append(data, temp...)
//
//	temp, e = PointArrayToBytes(&context.H)
//	if e != nil {
//		return nil, fmt.Errorf("Error in H: %s", e)
//	}
//	data = append(data, temp...)
//
//	temp, e = PointArrayToBytes(&context.R)
//	if e != nil {
//		return nil, fmt.Errorf("Error in R: %s", e)
//	}
//	data = append(data, temp...)
//
//	return data, nil
//}

///*PointArrayToBytes is a utility function to convert a abstract.Point array into []byte, used in signatures*/
//func PointArrayToBytes(array *[]kyber.Point) (data []byte, err error) {
//	for _, p := range *array {
//		temp, e := p.MarshalBinary()
//		if e != nil {
//			return nil, fmt.Errorf("Error in S: %s", e)
//		}
//		data = append(data, temp...)
//	}
//	return data, nil
//}
//
///*ScalarArrayToBytes is a utility function to convert a abstract.Scalar array into []byte, used in signatures*/
//func ScalarArrayToBytes(array *[]kyber.Scalar) (data []byte, err error) {
//	for _, s := range *array {
//		temp, e := s.MarshalBinary()
//		if e != nil {
//			return nil, fmt.Errorf("Error in S: %s", e)
//		}
//		data = append(data, temp...)
//	}
//	return data, nil
//}
