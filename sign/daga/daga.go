package daga

// TODO quick documentation and DAGA description with links to relevant parts of the Syta papers
// TODO see what to export and what not
// TODO see if better keep word for word terminology of daga paper or try to put more explanatory words

import (
	"fmt"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/group/edwards25519"
	"github.com/dedis/kyber/util/random"
)

// TODO  QUESTION see what to use: curve or suite ? + suite.find vs directly suite + have suite be a global parameter of the package ?
// TODO question when to introduce a new "suite" ? should I define a new suite to implement DAGA ?
// 		seems that the point of kyber is to abstract away actual crypto algorithms => use suite like in dkg
// 		but in this case we can silently introduce security bugs...

// TODO remember to don't tie daga to Curve25519 and allow 'injection' of any other group/signature scheme where the DAGA assumptions hold (e.g a schnorr group and "standard schnorr signature")
// TODO => create suite, or maybe bad idea ?


// TODO => can someone quickly introduce me to kyber, why kyber, why things are done like they are done, etc ?

//type Suite edwards25519.SuiteEd25519
// TODO instead of making Suite a type alias we need to carry around in functions that need it can we just declare a var package global Suite ?
var suite = edwards25519.NewBlakeSHA256Ed25519()

/*AuthenticationContext holds all the constants of a particular DAGA authentication round.

The DAGA authentication context is established and published 'collectively' by the servers before an authentication round.

G contains the 'group' (<- poor choice of word) definition, that is the public keys of the clients (G.X) and the servers (G.Y)
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
c holds the AuthenticationContext by the client to authenticate
s contains the client's commitments to the secrets shared with all the servers
*/
type authenticationMessage struct {
	c authenticationContext
	s  []kyber.Point
	t0 kyber.Point
	p0 clientProof
}

/*Client is used to store the client's private key and index.*/
type client struct {
	private kyber.Scalar
	index   int
}

/*clientProof stores the client's proof P as of "Syta - Identity Management Through Privacy Preserving Aut 4.3.7"
 */
type clientProof struct {
	cs kyber.Scalar
	t  []kyber.Point
	c  []kyber.Scalar
	r  []kyber.Scalar
}

/*NewClient is used to initialize a new client with a given index
If no private key is given, a random one is chosen
*/
func NewClient(i int, s kyber.Scalar) (client, error) {
	if i < 0 {
		return client{}, fmt.Errorf("invalid parameters")
	}
	if s == nil {
		// TODO suite.randomstream vs random.new vs ? too many ways of doing same thing no ?
		s = suite.NewKey(random.New())  // TODO seems that newkey is the way to go but is less generic than the previous method
		//s = suite.Scalar().Pick(suite.RandomStream())
	}
	return client{index: i, private: s}, nil
}

//GetPublicKey returns the public key associated with a client // TODO is it useful ? I'd say no or make it a method of scalar
func (client *client) getPublicKey() kyber.Point {
	suite.
	return suite.Point().Mul(client.private, nil)
	// FIXME create a new point just to call a "method" ... ?
	// it would be better if mul become a function no ? since it is nothing else that a function or maybe have a "singleton point"
	// or if we can obtain the mul "functionized" method from the real "point" type used in the suite i.e T.mul(point T, s Scalar, p Point)
}

/*CreateRequest generates the elements for the authentication request (T0, S) and the generation of the client's proof(s)*/
func (client *client) createRequest(context *authenticationContext) (T0 kyber.Point, S []kyber.Point, s kyber.Scalar, err error) {

	//Step 1: generate ephemeral DH key pair
	z := suite.NewKey(suite.RandomStream())  // TODO same "generic" question as usual
	Z := suite.Point().Mul(z, nil)

	//Step 2: generate shared secrets with the servers
	// TODO []byte to Scalar
	shared := make([][]byte, 0, len(context.g.y))
	for _, serverKey := range context.g.y {
		hasher := suite.Hash()
		// FIXME !! here to my understanding this is ok, we use sha256 => 32 bytes == size of scalar but what if another hash used ? ==> ok not the case I'll create a suite !
		// and why for kind of the exact same purpose EdDSA/25519 recommend to take the lower 256 bits of 512 bits hash ??
		// shouldn't we do the same even if it is not written in DAGA paper ? (that does not talk about elliptic curves)
		// + do we need to ensure that the unlikely 00000 hash never occurs ?
		_, err := suite.Point().Mul(z, serverKey).MarshalTo(hasher)
		if err != nil {
			// FIXME never happens or ??
			return nil, nil, nil, fmt.Errorf("error generating shared secrets: %s", err)
		}
		hash := hasher.Sum(nil)
		shared = append(shared, hash)
	}

	//Step 3: computes initial linkage tag and commitments to the shared secrets
	//Computes the value of the exponent for the initial linkage tag
	exp := suite.Scalar().One()
	for i := 0; i < len(context.g.y); i++ {
		rand := suite.Cipher(shared[i])
		exp.Mul(exp, suite.Scalar().Pick(rand))
	}
	T0 = suite.Point().Mul(context.H[client.index], exp)

	//Computes the commitments
	S = make([]kyber.Point, len(context.G.Y)+1)
	exp = suite.Scalar().One()
	for i := 0; i < len(context.G.Y)+1; i++ {
		S[i] = suite.Point().Mul(nil, exp)
		if i != len(context.G.Y) {
			rand := suite.Cipher(shared[i])
			exp.Mul(exp, suite.Scalar().Pick(rand))
		}
	}
	s = exp

	//Add the client's ephemeral public key to the commitments
	/*Prepend taken from comment at
	https://codingair.wordpress.com/2014/07/18/go-appendprepend-item-into-slice/ */
	S = append(S, nil)
	copy(S[1:], S)
	S[0] = Z

	return T0, S, s, nil
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
