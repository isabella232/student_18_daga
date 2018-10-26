package daga

import (
	"errors"
	"fmt"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/util/key"
	"strconv"
)

// TODO doc
type Client interface {
	PublicKey() kyber.Point
	PrivateKey() kyber.Scalar
	Index() int
	//NewAuthenticationMessage(suite Suite, context AuthenticationContext,
	//						 sendCommitsReceiveChallenge func([]kyber.Point)Challenge) (*AuthenticationMessage, error)
}

// minimum daga client containing nothing but what DAGA needs to work internally (and implement Client interface)
// used only for the test suite and/or to build other more complete Clients !
type minimumClient struct {
	key key.Pair
	index int
}

//returns the public key of the client/server
func (c minimumClient) PublicKey() kyber.Point {
	return c.key.Public
}

//returns the private key of the client/server
func (c minimumClient) PrivateKey() kyber.Scalar {
	return c.key.Private
}

//returns the client's (or server's) index in auth. contex
func (c minimumClient) Index() int {
	return c.index
}

// "philosophical" question
//func (c client) NewAuthenticationMessage(suite Suite, context AuthenticationContext,
//										 sendCommitsReceiveChallenge func([]kyber.Point)Challenge) (*AuthenticationMessage, error) {
//	return newAuthenticationMessage(suite, context, c, sendCommitsReceiveChallenge)
//
//}

//func ClientToBytes(c Client) (data []byte, err error) {
//	b, err := c.PublicKey().MarshalBinary()
//	if err != nil {
//		return nil, err
//	}
//	data = append(data, b...)
//	b, err = c.PrivateKey().MarshalBinary()
//	if err != nil {
//		return nil, err
//	}
//	data = append(data, b...)
//	b, err = c.Index().
//	if err != nil {
//		return nil, err
//	}
//	data = append(data, b...)
//}

// returns a Client that holds a newly allocated minimumClient initialized with index i and secret key s (if provided)
// if not provided a new key is picked at random
func NewClient(suite Suite, i int, s kyber.Scalar) (Client, error) {
	if i < 0 {
		return nil, errors.New("invalid parameters, negative index")
	}

	var kp *key.Pair
	if s == nil {
		kp = key.NewKeyPair(suite)
	} else {
		// FIXME check if s is a proper secret (see small subgroup attacks on some groups/curves).
		// FIXME .. or remove this option
		// FIXME .. or make it a proper secret..
		kp = &key.Pair{
			Private: s, // <- could (e.g. edwards25519) be attacked if not in proper form
			Public:  suite.Point().Mul(s, nil),
		}
	}

	return minimumClient{
		index: i,
		key:   *kp,
	}, nil
}

// authenticationMessage stores an authentication message request (M0)
// sent by a client to an arbitrarily chosen server (listed in the context).
//
// Upon receiving the client’s message, all servers collectively process M0
// and either accept or reject the client's authentication request.
//
// c holds the AuthenticationContext used by the client to authenticate.
//
// initialTagAndCommitments contains the client's commitments to the secrets shared with all the servers
// and the client's initial linkage tag (see initialTagAndCommitments).
//
// p0 is the client's proof that he correctly followed the protocols and
// that he belongs to the authorized clients in the context. (see ClientProof).
// TODO FIXME consider removing context from daga.authmsg, user code will send a request that will contain daga authmsg AND a context (this way user code can add practical info to context such as addresses etc..)
// this has been done in daga/cothority
type AuthenticationMessage struct {
	C AuthenticationContext
	initialTagAndCommitments
	P0 ClientProof
}

func NewAuthenticationMessage(suite Suite, context AuthenticationContext,
							  client Client,
	                          sendCommitsReceiveChallenge func([]kyber.Point)Challenge) (*AuthenticationMessage, error) {
	// TODO see if context big enough to justify transforming the parameter into *AuthenticationContext
	// TODO FIXME think where/when/how check context validity (points/keys don't have small order, generators are generators etc..)

	// FIXME create a validate context helper
	if len(context.ClientsGenerators()) <= client.Index() {
		return nil, errors.New("context not valid, or wrong client index")
	}

	// DAGA client Steps 1, 2, 3:
	_, Y := context.Members()
	TAndS, s := newInitialTagAndCommitments(suite, Y, context.ClientsGenerators()[client.Index()])

	// DAGA client Step 4: sigma protocol / interactive proof of knowledge PKclient, with one random server
	if P, err := newClientProof(suite, context, client, *TAndS, s, sendCommitsReceiveChallenge); err != nil {
		// TODO log QUESTION intro on the logging practises/conventions at DEDIS
		return nil, err
	} else {
		// DAGA client Step 5
		M0 := AuthenticationMessage{
			C:                        context,
			initialTagAndCommitments: *TAndS,
			P0:                       P,
		}
		return &M0, nil
	}
}

// validateAuthenticationMessage is an utility function to validate that a client message is correctly formed
func validateAuthenticationMessage(suite Suite, msg AuthenticationMessage) error {
	if msg.C == nil {
		return errors.New("validateAuthenticationMessage: nil context")
	}
	X, Y := msg.C.Members()
	//Number of clients
	i := len(X)
	//Number of servers
	j := len(Y)
	//A commitment for each server exists and the second element is the generator S=(Z,g,S1,..,Sj)
	if len(msg.SCommits) != j+2 {
		return fmt.Errorf("validateAuthenticationMessage: wrong number of commitments in sCommits (%d), expected: %d", len(msg.SCommits), j+2)
	}
	if !msg.SCommits[1].Equal(suite.Point().Base()) {
		return errors.New("validateAuthenticationMessage: second group element in sCommits is not the group generator")
	}
	//T0 not empty
	if msg.T0 == nil {
		return errors.New("validateAuthenticationMessage: initial tag T0 is nil")
	}
	//Proof fields have the correct size
	if len(msg.P0.C) != i || len(msg.P0.R) != 2*i || len(msg.P0.T) != 3*i || msg.P0.Cs == nil {
		return fmt.Errorf("validateAuthenticationMessage: malformed ClientProof, %v", msg.P0)
	}
	return nil
}

// Returns whether an authenticationMessage is valid or not, (well formed AND valid/accepted proof)
//
// msg the authenticationMessage to verify
func verifyAuthenticationMessage(suite Suite, msg AuthenticationMessage) error {
	if err := validateAuthenticationMessage(suite, msg); err != nil {
		return errors.New("verifyAuthenticationMessage:" + err.Error())
	}
	// TODO FIXME decide from where to pick the args when choice ! (from client msg or from server state ?)
	// FIXME here challenge ~~should~~ MUST be picked from server state IMO but QUESTION ask Ewa Syta
	// TODO resolve all these when building the actual service
	// related thread : https://github.com/dedis/student_18_daga/issues/24
	// => a solution maybe change ClientProof struct to embed Challenge struct (contains signatures) and new signed commitment struct
	if err := verifyClientProof(suite, msg.C, msg.P0, msg.initialTagAndCommitments); err != nil {
		return errors.New("verifyAuthenticationMessage:" + err.Error())
	}
	return nil
}

// initialTagAndCommitments stores :
//
// sCommits the client's commitments to the secrets shared with the servers.
// that is a set of commitments sCommits = { Z, S0, .., Sj, .., Sm } s.t.
// S0 = g, Sj = g^(∏sk : k=1..j) (see 4.3.5 client's protocols step 2-3).
//
// t0 the client's initial linkage tag. t0 = h^(∏sk : k=1..m)
//
// here above, (Z,z) is the client's ephemeral DH key pair, (see 4.3.5 client's protocols step 1)
// and sk=Hash1(Yk^z)
type initialTagAndCommitments struct {
	SCommits []kyber.Point
	T0       kyber.Point
}

// TODO later add logging where needed/desired
// TODO decide if better to make this function a method of client that accept context, or better add a method to client that use it internally
// Returns a pointer to a newly allocated initialTagAndCommitments struct correctly initialized
// and an opening s (product of all secrets that client shares with the servers) of Sm (that is needed later to build client's proof PKclient)
// (i.e. performs client protocols Steps 1,2 and 3)
//
// serverKeys the public keys of the servers (of a particular AuthenticationContext)
//
// clientGenerator the client's per-round generator
//
func newInitialTagAndCommitments(suite Suite, serverKeys []kyber.Point, clientGenerator kyber.Point) (*initialTagAndCommitments, kyber.Scalar) {
	// TODO parameter checking, what should we check ? assert that clientGenerator is indeed a generator of the group ?

	//DAGA client Step 1: generate ephemeral DH key pair
	ephemeralKey := key.NewKeyPair(suite)
	z := ephemeralKey.Private // FIXME how to erase ?
	Z := ephemeralKey.Public

	//DAGA client Step 2: generate shared secret exponents with the servers
	sharedSecrets := make([]kyber.Scalar, 0, len(serverKeys))
	for _, serverKey := range serverKeys {
		hasher := suite.Hash()
		// QUESTION ask Ewa Syta
		// can it be a problem if hash size = 256 > log(phi(group order = 2^252 + 27742317777372353535851937790883648493 prime))
		// because it is currently the case, to me seems that by having a hash size greater than the number of phi(group order)
		// it means that the resulting "pseudo random keys" will no longer have same uniform distribution since two keys can be = mod phi(group order).
		// (to my understanding secrets distribution will not be uniform and that kind of violate random oracle model assumption)
		// but since nothing is said about this concern in Curve25519 paper I'd say this is not an issue finally...
		suite.Point().Mul(z, serverKey).MarshalTo(hasher)
		hash := hasher.Sum(nil)
		sharedSecret := suite.Scalar().SetBytes(hash)
		// QUESTION FIXME mask the bits to avoid small subgroup attacks
		// (but think how an attacker could obtain sP where P has small order.. maybe this is not possible and hence protection irrelevant,
		// anyway to my understanding we lose nothing (security-wise) by always performing the bittwiddlings and we might lose security if we don't !
		// relevant link/explanations https://crypto.stackexchange.com/questions/12425/why-are-the-lower-3-bits-of-curve25519-ed25519-secret-keys-cleared-during-creati
		sharedSecrets = append(sharedSecrets, sharedSecret)
	} // QUESTION don't understand why sha3(sha512) was done by previous student instead of sha256 in the first place...? => I use only one hash (sha256 for now)

	//DAGA client Step 3: computes initial linkage tag and commitments to the shared secrets
	//	Computes the value of the exponent for the initial linkage tag
	exp := suite.Scalar().One()
	for _, sharedSecret := range sharedSecrets {
		exp.Mul(exp, sharedSecret)
	}
	T0 := suite.Point().Mul(exp, clientGenerator)

	//	Computes the commitments to the shared secrets
	S := make([]kyber.Point, 0, len(serverKeys)+2)
	S = append(S, Z, suite.Point().Base()) // Z, S0=g
	exp = sharedSecrets[0]                 // s1
	for _, sharedSecret := range sharedSecrets[1:] /*s2..sm*/ {
		S = append(S, suite.Point().Mul(exp, nil)) // S1..Sm-1
		exp.Mul(exp, sharedSecret)
	}
	S = append(S, suite.Point().Mul(exp, nil) /*Sm*/)
	s := exp

	return &initialTagAndCommitments{
		T0:       T0,
		SCommits: S,
	}, s
}

// GetFinalLinkageTag checks the server's signatures and proofs
// and outputs the final linkage tag or an error
func GetFinalLinkageTag(suite Suite, context AuthenticationContext, msg ServerMessage) (Tf kyber.Point, err error) {
	// FIXME QUESTION not sure that the verifyserverproof belongs inside this method in the client..DAGA paper specify that it is the servers that check it
	// + not sure that this is how things were intended in the paper, maybe redefine what is sent to the client ! (only the final tag...) but why not... as it is now..
	// TODO but guess this won't do any harm, will need to decide when building the service

	//Input checks
	if context == nil || len(msg.Tags) == 0 || len(msg.Tags) != len(msg.Proofs) || len(msg.Proofs) != len(msg.Sigs) || len(msg.Sigs) != len(msg.Indexes) {
		return nil, errors.New("invalid inputs")
	}

	data, e := msg.Request.ToBytes()
	if e != nil {
		return nil, fmt.Errorf("error in request: %s", e)
	}
	_, Y := context.Members()
	for i, p := range msg.Proofs {
		//verify signatures
		temp, err := msg.Tags[i].MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("error in tags: %s", err)
		}
		data = append(data, temp...)
		temp, err = p.ToBytes()
		if err != nil {
			return nil, fmt.Errorf("error in proofs: %s", err)
		}
		data = append(data, temp...)
		data = append(data, []byte(strconv.Itoa(msg.Indexes[i]))...)
		err = SchnorrVerify(suite, Y[msg.Sigs[i].Index], data, msg.Sigs[i].Sig)
		if err != nil {
			return nil, fmt.Errorf("error in signature: %d\n%s", i, err)
		}
		//verify proofs
		var valid bool
		if p.R2 == nil {
			valid = verifyMisbehavingProof(suite, Y[i], &p, msg.Request.SCommits[0])
		} else {
			valid = verifyServerProof(suite, context, i, &msg)
		}
		if !valid {
			return nil, errors.New("invalid server proof")
		}
	}
	return msg.Tags[len(msg.Tags)-1], nil
}