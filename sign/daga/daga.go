// TODO quick documentation and DAGA description with links to relevant parts of the Syta papers
package daga

// TODO decide / review method vs functions + "granularity of parameters"
// I'd say put DAGA "primitives" as functions and create methods on clients and servers that use those,
// put the daga primitives into kyber and the rest into a DAGA package somewhere else in cothority
// TODO QUESTION FIXME how to securely erase secrets ?
// TODO see what to export and what not, for now mostly everything private
import (
	"errors"
	"fmt"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/sign/schnorr"
	"github.com/dedis/kyber/util/key"
	"hash"
)

// Suite represents the set of functionalities needed for the DAGA package to operate
// the purpose of the Suite is to allow multiple implementations,
// (e.g one using EC crypto on edwards25519 curve and another one using a Schnorr group like in the original DAGA paper,
// originally "DAGA assumes a cyclic multiplicative group G of prime order q, where p=2q+1,
// where the Discrete Logarithm and Decisional Diffie-Hellman assumptions hold"
// quoted from Syta - Identity Management Through Privacy Preserving Aut)
//
// concrete suites are defined in daga/suite.go
type Suite interface {
	kyber.Group
	kyber.Random
	key.Generator     // needed since sometimes/in some groups we need to take care while generating secrets, (e.g in edwards25519, to avoid small subgroup attacks, need to mask some bits)
	kyber.HashFactory // FIXME remove this hashfactory and defines hash1 hash2 as hash functions that should behaves like RO and that returns scalars and points respectively
	// FIXME review where Hash2 should be called instead of Hash and how, I might have used Hash everywhere, bad
	hashTwo() hash.Hash // DAGA needs another hash function (that can be of another size depending on the concrete groups used)
}

// TODO it is the user of our package that defines such a variable/suite
// => will need to add a parameter to all daga functions and methods where needed
var suite = NewSuiteEC()

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
// See Syta - Identity Management Through Privacy Preserving Aut Chapter 4.7.3

// g contains the 'group' (<- poor choice of word) definition, that is the public keys of the clients (g.x) and the servers (g.y)
//
// r contains the commitments of the servers to their unique per-round secrets
//
// h contains the unique per-round generators of the group (<- the algebraic structure) associated to each clients
// TODO maybe remove the g thing (but we lose reading "compatibility with daga paper") and have a slices of struct {x, h} and struct {y, r} instead to enforce same length
type authenticationContext struct {
	g struct {
		x []kyber.Point
		y []kyber.Point
	}
	r []kyber.Point
	h []kyber.Point
}

// returns a pointer to a newly allocated authenticationContext initialized with :
//
// x the public keys of the clients
//
// y the public keys of the servers
//
// r the commitments of the servers to their unique per-round secrets
//
// h the unique per-round generators of the group associated to each clients
func NewAuthenticationContext(x, y, r, h []kyber.Point) (*authenticationContext, error) {
	if len(x) != len(h) || len(y) != len(r) || len(x) == 0 || len(y) == 0 {
		return nil, errors.New("NewAuthenticationContext: illegal length, len(x) != len(h) Or len(y) != len(r) Or zero length slices")
	}
	return &authenticationContext{
		g: struct {
			x []kyber.Point
			y []kyber.Point
		}{
			x: x,
			y: y,
		},
		r: r,
		h: h,
	}, nil
}

// returns the public keys of the members of an authenticationContext, client keys in X and server keys in Y
func (ac authenticationContext) Members() (X, Y []kyber.Point) {
	return ac.g.x, ac.g.y
}

// authenticationMessage stores an authentication message request (M0)
// sent by a client to an arbitrarily chosen server (listed in the context).
//
// Upon receiving the client’s message, all servers collectively process M0
// and either accept or reject the client's authentication request.
//
// c holds the authenticationContext used by the client to authenticate.
//
// initialTagAndCommitments contains the client's commitments to the secrets shared with all the servers
// and the client's initial linkage tag (see initialTagAndCommitments).
//
// p0 is the client's proof that he correctly followed the protocol and
// that he belongs to the authorized clients in the context. (see clientProof).
type authenticationMessage struct {
	c authenticationContext
	initialTagAndCommitments
	p0 clientProof
}

// initialTagAndCommitments stores :
//
// sCommits the client's commitments to the secrets shared with the servers.
// that is a set of commitments sCommits = { Z, S0, .., Sj, .., Sm } s.t.
// S0 = g, Sj = g^(∏sk : k=1..j) (see 4.3.5 client's protocol step 2-3).
//
// t0 the client's initial linkage tag. t0 = h^(∏sk : k=1..m)
//
// here above, (Z,z) is the client's ephemeral DH key pair, (see 4.3.5 client's protocol step 1)
// and sk=Hash1(Yk^z)
type initialTagAndCommitments struct {
	sCommits []kyber.Point
	t0       kyber.Point
}

// Client is used to store a client's key pair and index.
type Client struct {
	key   key.Pair
	index int
}

// NewClient is used to initialize a new client with a given index
// If no private key is given, a random one is chosen
// TODO see how this i will be handled...when building the service/protocoles conodes etc..
func NewClient(i int, s kyber.Scalar) (*Client, error) {
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

	return &Client{
		index: i,
		key:   *kp,
	}, nil
}

// TODO later add logging where needed/desired
// TODO decide if better to make this function a method of client that accept context, or better add a method to client that use it internally
// Returns a pointer to a newly allocated initialTagAndCommitments struct correctly initialized
// and an opening s (product of all secrets that client shares with the servers) of Sm (that is needed later to build client's proof PKclient)
// (i.e. performs client protocol Steps 1,2 and 3)
//
// serverKeys the public keys of the servers (of a particular authenticationContext)
//
// clientGenerator the client's per-round generator
//
func newInitialTagAndCommitments(serverKeys []kyber.Point, clientGenerator kyber.Point) (*initialTagAndCommitments, kyber.Scalar) {
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
		t0:       T0,
		sCommits: S,
	}, s
}

// Returns the client's DH public key
func (c Client) PublicKey() kyber.Point {
	return c.key.Public
}

func (c Client) NewAuthenticationMessage(context authenticationContext) (*authenticationMessage, error) {
	// TODO see if context big enough to justify transforming the parameter into *authenticationContext
	// TODO FIXME think where/when/how check context validity (points/keys don't have small order, generators are generators etc..)
	// DAGA client Steps 1, 2, 3:
	TAndS, s := newInitialTagAndCommitments(context.g.y, context.h[c.index])

	// TODO server selection and circuit establishment (use roster infos etc..)
	// TODO pick random server and find its location (use roster infos etc..)
	// TODO establish circuit/channel from/to server => using onet/cothority facilities
	// TODO net encode/decode data (if needed/not provided by onet/cothority)
	// TODO see cothority template, on reception of a challenge message (to define) from the network pipe it into the pullChallenge chan => register an handler that do that
	// TODO  ''  , on reception of the commitments from the pushCommitments channel pipe them to the remote server over the network
	var pushCommitments chan []kyber.Point
	var pullChallenge chan Challenge

	// DAGA client Step 4: sigma protocol / interactive proof of knowledge PKclient, with one random server
	if P, err := newClientProof(context, c, *TAndS, s, pushCommitments, pullChallenge); err != nil {
		// TODO log QUESTION can I have an intro on the logging practises at DEDIS
		return nil, err
	} else {
		// DAGA client Step 5
		M0 := authenticationMessage{
			c:                        context,
			initialTagAndCommitments: *TAndS,
			p0:                       P,
		}
		return &M0, nil
	}
}

// TODO add a server method that use it or in fact make it a server method ... !
// Returns whether an authenticationMessage is valid or not, (well formed AND valid/accepted proof)
//
// msg the authenticationMessage to verify
func verifyAuthenticationMessage(msg authenticationMessage) bool {
	// FIXME return value make it return an error instead !
	// TODO FIXME see where to put this one, just saw that serverprotocol calls validate then verify, but maybe other code expect verify to validate
	if !validateClientMessage(msg) {
		return false
	}
	// TODO FIXME decide from where to pick the args when choice ! (from client msg or from server state ?)
	// FIXME here challenge should be picked from server state IMO but QUESTION ask Ewa Syta !
	// TODO resolve all these when building the actual service
	return verifyClientProof(msg.c, msg.p0, msg.initialTagAndCommitments) == nil
}

// Signs using schnorr signature scheme over the group of the Suite
// QUESTION to me this is a bad idea ?! better to have Sign be a required function listed in the Suite,
// QUESTION where concrete suite implementation make sure that the signature scheme works well with the chosen group etc..
func SchnorrSign(private kyber.Scalar, msg []byte) (s []byte, err error) {
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
func SchnorrVerify(public kyber.Point, msg, sig []byte) (err error) {
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

/*ToBytes is a utility functton to convert a ContextEd25519 into []byte, used in signatures*/
// QUESTION WTF no other way ?
func (context *authenticationContext) ToBytes() (data []byte, err error) {
	temp, e := PointArrayToBytes(context.g.x)
	if e != nil {
		return nil, fmt.Errorf("Error in X: %s", e)
	}
	data = append(data, temp...)

	temp, e = PointArrayToBytes(context.g.y)
	if e != nil {
		return nil, fmt.Errorf("Error in Y: %s", e)
	}
	data = append(data, temp...)

	temp, e = PointArrayToBytes(context.h)
	if e != nil {
		return nil, fmt.Errorf("Error in H: %s", e)
	}
	data = append(data, temp...)

	temp, e = PointArrayToBytes(context.r)
	if e != nil {
		return nil, fmt.Errorf("Error in R: %s", e)
	}
	data = append(data, temp...)

	return data, nil
}

/*PointArrayToBytes is a utility function to convert a kyber.Point array into []byte, used in signatures*/
// QUESTION same as above + if this is the way to go make it a method of []kyber.Point for consistency
func PointArrayToBytes(array []kyber.Point) (data []byte, err error) {
	for _, p := range array {
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
func ScalarArrayToBytes(array []kyber.Scalar) (data []byte, err error) {
	for _, s := range array {
		temp, e := s.MarshalBinary()
		if e != nil {
			return nil, fmt.Errorf("Error in S: %s", e)
		}
		data = append(data, temp...)
	}
	return data, nil
}
