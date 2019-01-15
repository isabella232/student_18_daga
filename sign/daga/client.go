package daga

import (
	"errors"
	"fmt"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/util/key"
	"strconv"
)

// Client represents an entity (see terminology in "Syta - Identity Management Through Privacy Preserving Aut 2.3)".
// that can authenticate as a member of a group using DAGA.
// Interface for flexibility and to allow possibly different implementations, ease testing etc.,
// defines the method that other DAGA primitives expect/need to do their job.
type Client interface {
	PublicKey() kyber.Point
	PrivateKey() kyber.Scalar
	Index() int
	//NewAuthenticationMessage(suite Suite, context AuthenticationContext,
	//						 sendCommitsReceiveChallenge func([]kyber.Point)Challenge) (*AuthenticationMessage, error)
}

// minimum daga client containing nothing but what DAGA needs to work internally (and implement Client interface)
// used only for the test suite and/or to build other more complete Clients (e.g. done in dagacothority)
type minimumClient struct {
	key   key.Pair
	index int
}

// PublicKey returns the public key of the client/server
func (c minimumClient) PublicKey() kyber.Point {
	return c.key.Public
}

// PrivateKey returns the private key of the client/server
func (c minimumClient) PrivateKey() kyber.Scalar {
	return c.key.Private
}

// Index returns the client's (or server's) index in auth. context
func (c minimumClient) Index() int {
	return c.index
}

// TODO "philosophical" question
//func (c client) NewAuthenticationMessage(suite Suite, context AuthenticationContext,
//										 sendCommitsReceiveChallenge PKclientVerifier) (*AuthenticationMessage, error) {
//	return newAuthenticationMessage(suite, context, c, sendCommitsReceiveChallenge)
//
//}

// NewClient returns a Client that holds a newly allocated minimumClient initialized with index i and secret key s (if provided)
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
		// FIXME .. or trust user to not shoot itself in the foot
		// FIXME .. or don't care and see later when usage/contract/etc of edwards25519 clearly defined
		//  and issue regarding key generator fixed (https://github.com/dedis/kyber/issues/351)
		kp = &key.Pair{
			Private: s, // <- could (e.g. edwards25519) be attacked if not in proper form
			Public:  suite.Point().Mul(s, nil),
		}
	}

	// FIXME use something similar to https://github.com/awnumar/memguard to protect the secret key
	return minimumClient{
		index: i,
		key:   *kp,
	}, nil
}

// AuthenticationMessage stores an authentication message request (M0)
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
type AuthenticationMessage struct {
	C AuthenticationContext
	initialTagAndCommitments
	P0 ClientProof
}

// NewAuthenticationMessage returns a pointer to a new AuthenticationMessage for/under `context` by `client`.
// it performs the daga client protocol:
// 	- PKclient proof of knowledge with a PKclientVerifier (`sendCommitsReceiveChallenge` abstraction of remote proof verifiers)
//	- assemble everything
func NewAuthenticationMessage(suite Suite, context AuthenticationContext,
	client Client,
	sendCommitsReceiveChallenge PKclientVerifier) (*AuthenticationMessage, error) {

	if len(context.ClientsGenerators()) <= client.Index() || ValidateContext(context) != nil {
		return nil, errors.New("context not valid, or wrong client index")
	}

	// DAGA client Steps 1, 2, 3:
	members := context.Members()
	TAndS, s := newInitialTagAndCommitments(suite, members.Y, context.ClientsGenerators()[client.Index()])

	// DAGA client Step 4: sigma protocol / interactive proof of knowledge PKclient, with one random server (abstracted by sendCommitsReceiveChallenge)
	if P, err := newClientProof(suite, context, client, *TAndS, s, sendCommitsReceiveChallenge); err != nil {
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
	members := msg.C.Members()
	//Number of clients
	i := len(members.X)
	//Number of servers
	j := len(members.Y)
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
	if len(msg.P0.C) != i || len(msg.P0.R) != 2*i || len(msg.P0.T) != 3*i || msg.P0.Cs.Cs == nil {
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

// Returns a pointer to a newly allocated initialTagAndCommitments struct correctly initialized
// and an opening s (product of all secrets that client shares with the servers) of Sm (that is needed later to build client's proof PKclient)
// (i.e. performs client protocols Steps 1,2 and 3)
//
// serverKeys the public keys of the servers (of a particular AuthenticationContext)
//
// clientGenerator the client's per-round generator
//
func newInitialTagAndCommitments(suite Suite, serverKeys []kyber.Point, clientGenerator kyber.Point) (*initialTagAndCommitments, kyber.Scalar) {

	// QUESTION here assert that client generator is indeed a generator of the prime order group ?
	//  (should not be needed if we are only concerned with DH on curve25519
	//  => because all secrets should be multiple of 8 (not the case in kyber, bug)
	//  => even if attacker provides a point in 8th order subgroup => cannot learn anything)
	//  but still this is a valid concern since:
	//  1) if we change the concrete suite implementation, we would like the code to remain correct
	//  2) we are not only concerned with DH on 25519 (see also related comment below and in gencontext.go),
	//  	if we don't check generator in correct subgroup somewhere
	//  	=> can compromize auth. anonymity via T0 (even with 25519 based group and correct secrets)
	// 	TL;DR
	// 	choices:
	// 	1) rely only on anytrust and assume context (and generators)correctly generated if context validates
	// 	(properly signed by all servers, checked in ValidateContext) (WHAT WE DO NOW, with cothority implementation)
	// 	2) or check point before each usage here (or both..need to see how costly it is..could be only g^8 =?= 1)
	// 	IMHO somewhat 1) > 2) since 2) would probably need to verify different things or in a different way depending on the concrete algebraic group used
	// 	=> TODO decide what to do when rewriting server part and user-code facing API (notably to ease context generation, fix server.go uglinesses etc..)

	//DAGA client Step 1: generate ephemeral DH key pair
	ephemeralKey := key.NewKeyPair(suite)
	z := ephemeralKey.Private // FIXME how to securely erase it ? => maybe use https://github.com/awnumar/memguard !!
	Z := ephemeralKey.Public

	//DAGA client Step 2: generate shared secret exponents with the servers
	sharedSecrets := make([]kyber.Scalar, 0, len(serverKeys))
	for _, serverKey := range serverKeys {
		// shared secret = suite.Hash(DH(z, Y))
		hasher := suite.Hash()
		suite.Point().Mul(z, serverKey).MarshalTo(hasher)
		hash := hasher.Sum(nil)
		sharedSecret := suite.Scalar().SetBytes(hash)
		// QUESTION: do we need to mask the resulting bits (sharedSecret) to avoid small subgroup attacks (e.g. Lim and Lee + pollard kangaroo) ?
		//  (if we consider them effective..but then becomes tied to edwards25519 group..=> need to use suite.NewKey with a stream built from the hash)
		// 	e.g. if clientGenerator is not a generator (is not in (cyclic)subgroup of prime order generated by base) and has order 8,
		// 	then an attacker can know s mod 8 easily (from T0 and brute force) ! => may help him to break anonymity (e.g using Pollard kangaroo/lambda on a smaller set)
		// 	(or trivially by checking order..!!if attacker can set generator of a target to a point of order 8 I'd say already gameover!! see comment above)
		// 	anyway to my understanding we lose nothing (security-wise) by always performing the bit-twiddlings
		// 	(security tied to order of subgroup (~2^252) and discretelog complexity (~O(sqrt(l)) => ~126 bits)
		// 	and we might lose security if we don't !, if attacker control every server but one (the kth) and manage to succesfully retrieve s_k using the described trick and luck => can expose client
		// 	relevant links/explanations:
		// 	https://crypto.stackexchange.com/questions/12425/why-are-the-lower-3-bits-of-curve25519-ed25519-secret-keys-cleared-during-creati
		// 	https://eprint.iacr.org/2016/995.pdf
		//
		// 	ANSWER:TL;DR:conclusion:
		// 	if we are only concerned with DH on 25519, masks the bits => don't need to check order of point/generator
		// 	however we are not simply using DH, we use the shared secret as exponent to build tags !!,
		// 	if we don't check the order of the point and hence that generator is a correct daga round generator for client
		// 	=> can possibly break anonymity of client
		// 	=> client NEED to check/verify that generator correct (or trust them via anytrust) => in that case we don't need to masks the bits (to my current understanding)
		// 		-downside is we don't fully benefit from using bernstein's curve and X25519 function (if implemented by kyber..not clear, probably not)
		//		and RFC and bernstein paper REQUIRES to tweak the bits of the scalar (maybe required by underlying X25519 function don't know)
		//		and this is probably needed to interface with other crypto library/eventual other implementations (far hypothetical future...)
		// 	 	-additional benefits (matter of point of view..) is that now checks/concerns are more the same for EC crypto and traditional schnorr group crypto
		sharedSecrets = append(sharedSecrets, sharedSecret)
	}

	//DAGA client Step 3: computes initial linkage tag and commitments to the shared secrets
	//	Computes the value of the exponent for the initial linkage tag
	exp := suite.Scalar().One()
	for _, sharedSecret := range sharedSecrets {
		exp.Mul(exp, sharedSecret)
	}
	T0 := suite.Point().Mul(exp, clientGenerator)

	//	Computes the commitments to the shared secrets, S=(Z, S0, S1, .., Sm) // TODO merge with previous loop
	S := make([]kyber.Point, 0, len(serverKeys)+2)
	S = append(S, Z, suite.Point().Base()) // append Z, S0=g
	exp = sharedSecrets[0]                 // s1
	for _, sharedSecret := range sharedSecrets[1:] {  // s2..sm
		S = append(S, suite.Point().Mul(exp, nil))  // append S1..Sm-1
		exp.Mul(exp, sharedSecret)
	}
	S = append(S, suite.Point().Mul(exp, nil))  // append Sm
	s := exp

	return &initialTagAndCommitments{
		T0:       T0,
		SCommits: S,
	}, s
}

// GetFinalLinkageTag checks the server's signatures and proofs
// and outputs the final linkage tag or an error
func GetFinalLinkageTag(suite Suite, context AuthenticationContext, msg ServerMessage) (Tf kyber.Point, err error) {
	// FIXME not sure that the verifyserverproof belongs inside this method in the client..DAGA paper specify that it is the servers that check it
	//   + not sure that this is how things were intended in the paper, maybe redefine what is sent to the client ! (only the final tag...) but why not... as it is now..
	//   => see the remarks in server.go, address those when rewriting the API, and notice that "anytrust + all server proofs => deniability ko, some client authenticated for sure

	//Input checks
	if context == nil || len(msg.Tags) == 0 || len(msg.Tags) != len(msg.Proofs) || len(msg.Proofs) != len(msg.Sigs) || len(msg.Sigs) != len(msg.Indexes) {
		return nil, errors.New("invalid inputs")
	}

	data, e := msg.Request.ToBytes()
	if e != nil {
		return nil, fmt.Errorf("error in request: %s", e)
	}
	members := context.Members()
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
		err = SchnorrVerify(suite, members.Y[msg.Sigs[i].Index], data, msg.Sigs[i].Sig)
		if err != nil {
			return nil, fmt.Errorf("error in signature: %d\n%s", i, err)
		}
		//verify proofs
		var valid bool
		if p.R2 == nil {
			valid = verifyMisbehavingProof(suite, members.Y[i], &p, msg.Request.SCommits[0])
			// TODO and then if valid, what ??...
		} else {
			valid = verifyServerProof(suite, context, i, &msg)
		}
		if !valid {
			return nil, errors.New("invalid server proof")
		}
	}
	return msg.Tags[len(msg.Tags)-1], nil
}
