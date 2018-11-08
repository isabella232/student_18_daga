package daga

// FIXME audit/verify + rename "everything" + maybe see how to nicify external api (make some functions methods etc..)

import (
	"crypto/sha512"
	"errors"
	"fmt"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/util/key"
	"io"
	"strconv"
)

// TODO doc
type Server interface {
	Client                     // client interface (a server can be a client.. why not..)
	RoundSecret() kyber.Scalar //Per round secret
	SetRoundSecret(scalar kyber.Scalar)
	//NewChallengeCommitment(suite Suite) (*ChallengeCommitment, kyber.Scalar, error)
}

type server struct {
	Client
	r kyber.Scalar //Per round secret
}

//NewServer is used to initialize a new server with a given index
//If no private key is given, a random one is chosen
func NewServer(suite Suite, i int, s kyber.Scalar) (Server, error) {
	client, err := NewClient(suite, i, s)
	if err != nil {
		return nil, errors.New("NewServer: " + err.Error())
	}
	return &server{
		Client: client,
	}, nil
}

//returns the (current) per round (auth. round) secret of the server
func (s server) RoundSecret() kyber.Scalar {
	return s.r
}

//set the server's round secret to be the provided secret
func (s *server) SetRoundSecret(secret kyber.Scalar) {
	s.r = secret
}

// "philosophical" decision either stick with first idea of designing daga in kyber as a set of functions/primitives
// to be used by user implementations
// or make them methods on clients / servers etc..
//func (s server) NewChallengeCommitment(suite Suite) (commit *ChallengeCommitment, opening kyber.Scalar, err error) {
//	// TODO move content of newChallengeCommitment here
//	return newChallengeCommitment(suite, &s)
//}

/*ServerMessage stores the message sent by a server to one or many others*/
type ServerMessage struct {
	Request AuthenticationMessage
	Tags    []kyber.Point
	Proofs  []ServerProof
	Indexes []int
	Sigs    []ServerSignature
}

/*ChallengeCommitment stores the index of the server, the commitment value and the signature for the commitment*/
type ChallengeCommitment struct {
	Commit kyber.Point
	ServerSignature
}

/*ServerSignature stores a signature created by a server and the server's index*/
// FIXME see why index needed and if we cannot get rid of it, when receiveing a challengecommit the receiver knows who the sender is
// > can probably know its public key => can probably verify signature without looking it up in context using index
// mhh seems that it is only used to check/assert same index when traversing the slice of commitments in verify... maybe remove it..
// + TODO use different types for different signatures...pffff rhaa
type ServerSignature struct {
	Index int
	Sig   []byte
}

// Challenge stores the collectively generated challenge and the signatures of the servers
// This is the structure sent to the client as part of client proof PKclient
type Challenge struct {
	Cs   kyber.Scalar
	Sigs []ServerSignature  //Signatures for cs||PKClientCommitments
}

// verify all the signatures in the Challenge + verify that there are no duplicates
func (c Challenge) VerifySignatures(suite Suite, serverKeys []kyber.Point, pkClientCommitments []kyber.Point) error {
	if signData, err := c.ToBytes(pkClientCommitments); err != nil {
		return err
	} else {
		encountered := map[int]bool{}
		for _, sig := range c.Sigs {
			if encountered[sig.Index] == true {
				return fmt.Errorf("duplicate signature")
			}
			encountered[sig.Index] = true

			if err := SchnorrVerify(suite, serverKeys[sig.Index], signData, sig.Sig); err != nil {
				return errors.New("failed to verify signature of server " + strconv.Itoa(sig.Index) + ": " + err.Error())
			}
		}
		return nil
	}
}

// used for Challenge signatures, marshall the master challenge and concat with the PKclient's commitments
func (c Challenge) ToBytes(pkClientCommitments []kyber.Point) ([]byte, error) {
	csBytes, err := c.Cs.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("error marshalling master challenge: %s", err)
	}
	pkcCommitsBytes, err := PointArrayToBytes(pkClientCommitments)
	if err != nil {
		return nil, fmt.Errorf("error marshalling PKClient commitments: %s", err)
	}
	signData := append(csBytes, pkcCommitsBytes...)
	return signData, nil
}

/*ChallengeCheck stores all the information passed along the servers to check and sign the challenge*/
type ChallengeCheck struct {
	Challenge
	Commits  []ChallengeCommitment
	Openings []kyber.Scalar
}

/*ServerProof stores a server proof of his computations*/
type ServerProof struct {
	T1 kyber.Point
	T2 kyber.Point
	T3 kyber.Point
	C  kyber.Scalar
	R1 kyber.Scalar
	R2 kyber.Scalar
}

/*NewChallengeCommitment creates the server's commitment and its opening for the distributed challenge generation*/
func NewChallengeCommitment(suite Suite, server Server) (commit *ChallengeCommitment, opening kyber.Scalar, err error) {
	opening = suite.Scalar().Pick(suite.RandomStream())
	com := suite.Point().Mul(opening, nil)
	msg, err := com.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode commitment: %s", err)
	}
	sig, err := SchnorrSign(suite, server.PrivateKey(), msg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign commitment: %s", err)
	}
	return &ChallengeCommitment{
		ServerSignature: ServerSignature{
			Index: server.Index(),
			Sig:   sig,
		},
		Commit: com,
	}, opening, nil
}

func VerifyChallengeCommitmentSignature(suite Suite, commit ChallengeCommitment, pubKey kyber.Point) error {
	// QUESTION FIXME: How to check that a point is on the curve (and correct subgroup of curve) ? (don't remember why but the answer is you don't need if you use edwards curve25519)
	// FIXME but still this is a valid concern since if we change the curve/suite_implementation we would like the code to remain correct or ?
	//Convert the commitment and verify the signature
	msg, err := commit.Commit.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to encode commitment: %s", err)
	}
	err = SchnorrVerify(suite, pubKey, msg, commit.Sig)
	if err != nil {
		return fmt.Errorf("failed to verify signature of %dth server's commitment: %s", commit.Index, err)
	}
	return nil
}

// FIXME remove probably, unused and maybe..bof
/*VerifyChallengeCommitmentsSignatures verifies that all the commitments are valid and correctly signed*/
func VerifyChallengeCommitmentsSignatures(suite Suite, context AuthenticationContext, commits []ChallengeCommitment) error {
	for i, com := range commits {
		if i != com.Index {
			return fmt.Errorf("wrong commitment index: got %d expected %d", com.Index, i)
		}
		_, Y := context.Members()
		if err := VerifyChallengeCommitmentSignature(suite, com, Y[i]); err != nil {
			return err
		}
	}
	return nil
}

// returns whether opening is a valid opening of commitment
func CheckOpening(suite Suite, commitment kyber.Point, opening kyber.Scalar) bool {
	return commitment.Equal(suite.Point().Mul(opening, nil))
}

/*CheckOpenings verifies each commitment/opening and returns the computed master challenge*/
func checkOpenings(suite Suite, context AuthenticationContext, commits []ChallengeCommitment, openings []kyber.Scalar) (cs kyber.Scalar, err error) {
	// FIXME rename (compute master challenge + verify)
	if context == nil {
		return nil, fmt.Errorf("empty context")
	}
	_, Y := context.Members()
	if len(commits) != len(Y) {
		return nil, fmt.Errorf("incorrect number of commits: got %d expected %d", len(commits), len(Y))
	}
	if len(openings) != len(Y) {
		return nil, fmt.Errorf("incorrect number of openings: got %d expected %d", len(openings), len(Y))
	}

	cs = suite.Scalar().Zero()
	for i := 0; i < len(commits); i++ {
		if !CheckOpening(suite, commits[i].Commit, openings[i]) {
			return nil, fmt.Errorf("mismatch opening for server %d", i)
		}
		cs = suite.Scalar().Add(cs, openings[i])
	}
	return cs, nil
}

/*InitializeChallenge creates a ChallengeCheck structure, It checks the openings before doing so*/
func InitializeChallenge(suite Suite, context AuthenticationContext, commits []ChallengeCommitment, openings []kyber.Scalar) (*ChallengeCheck, error) {
	if context == nil || len(commits) == 0 || len(commits) != len(openings) {
		return nil, fmt.Errorf("invalid inputs")
	}

	// FIXME maybe remove completely the function, checkOpening will already be done by CheckUpdateChallenge (RHAAAAA)
	cs, err := checkOpenings(suite, context, commits, openings)
	if err != nil {
		return nil, err
	}

	return &ChallengeCheck{Challenge: Challenge{Cs:cs, Sigs:nil}, Commits: commits, Openings: openings}, nil
}

/*CheckUpdateChallenge verifies that all the previous servers computed the same challenges and that their signatures are valid
It also adds the server's signature to the list if the round-robin is not completed (the challenge has not yet made it back to the leader)
It must be used after the leader ran InitializeChallenge and after each server received the challenge from the previous server*/
func CheckUpdateChallenge(suite Suite, context AuthenticationContext, challengeCheck *ChallengeCheck, pkClientCommitments []kyber.Point, server Server) error {
	//Check the signatures and check for duplicates
	_, Y := context.Members()
	if err := challengeCheck.Challenge.VerifySignatures(suite, Y, pkClientCommitments); err != nil {
		return fmt.Errorf("CheckUpdateChallenge: %s", err)
	}

	//Checks the signatures of the commitments
	if err := VerifyChallengeCommitmentsSignatures(suite, context, challengeCheck.Commits); err != nil {
		return fmt.Errorf("CheckUpdateChallenge: failed to verify commitment signature %s", err)
	}
	//Checks the openings
	cs, err := checkOpenings(suite, context, challengeCheck.Commits, challengeCheck.Openings)
	if err != nil {
		return fmt.Errorf("CheckUpdateChallenge: failed to verify commitment openings %s", err)
	}
	//Checks that the challenge values match
	if !cs.Equal(challengeCheck.Cs) {
		return fmt.Errorf("CheckUpdateChallenge: master challenge values does not match")
	}

	//Add the server's signature to the list if it is not the last challengeCheck call (by leader/root once every server added its grain of salt)
	if len(challengeCheck.Sigs) == len(Y) {
		return nil
	}
	signData, err := challengeCheck.Challenge.ToBytes(pkClientCommitments)
	if err != nil {
		return fmt.Errorf("CheckUpdateChallenge: %s", err)
	}
	sig, err := SchnorrSign(suite, server.PrivateKey(), signData)
	if err != nil {
		return fmt.Errorf("CheckUpdateChallenge: failed to sign master challenge")
	}

	// FIXME why not store it at index ?
	challengeCheck.Sigs = append(challengeCheck.Sigs, ServerSignature{Index: server.Index(), Sig: sig})

	return nil
}

/*FinalizeChallenge is used to convert the data passed between the servers into the challenge sent to the client
It must be used after the leader got the message back and ran CheckUpdateChallenge*/
func FinalizeChallenge(context AuthenticationContext, challenge *ChallengeCheck) (Challenge, error) {
	if context == nil || challenge == nil {
		return Challenge{}, fmt.Errorf("invalid inputs")
	}
	_, Y := context.Members()
	if len(challenge.Sigs) != len(Y) {
		return Challenge{}, fmt.Errorf("signature count does not match: got %d expected %d", len(challenge.Sigs), len(Y))
	}

	return Challenge{Cs: challenge.Cs, Sigs: challenge.Sigs}, nil
}

//InitializeServerMessage creates a ServerMessage from a ClientMessage to ease further processing
// FIXME QUESTION rename .. New..
func InitializeServerMessage(request *AuthenticationMessage) (msg *ServerMessage, err error) {
	if request == nil {
		return nil, errors.New("InitializeServerMessage: request is nil")
	}
	return &ServerMessage{
		Request: *request,
		Tags:    nil,
		Indexes: nil,
		Proofs:  nil,
		Sigs:    nil,
	}, nil
}

/*ServerProtocol runs the server part of DAGA upon receiving a message from either a server or a client*/
// TODO DRY see what can be shared with GetFinalLinkageTag ...
func ServerProtocol(suite Suite, msg *ServerMessage, server Server) error {

	// input checks
	if msg == nil || len(msg.Indexes) != len(msg.Proofs) || len(msg.Proofs) != len(msg.Tags) || len(msg.Tags) != len(msg.Sigs) {
		return fmt.Errorf("ServerProtocol: invalid message")
	}

	//Step 1
	//Verify that the client's message is correctly formed and its proof correct
	if err := verifyAuthenticationMessage(suite, msg.Request); err != nil {
		return errors.New("ServerProtocol: malformed client message or wrong proof")
	}

	context := msg.Request.C

	_, Y := context.Members()
	//Checks that not all servers already did the protocols
	if len(msg.Indexes) >= len(Y) {
		return fmt.Errorf("ServerProtocol: too many calls of the protocols") //... ok... smells like fish..
	}

	// Iteratively checks each signature if this is not the first server to receive the client's request
	// FIXME dafuck is this ? nowhere to be found in DAGA or ?? is it out of scope ?? (to me it should be the network/session layer that perform those checks...)
	data, e := msg.Request.ToBytes()
	if e != nil {
		return errors.New("ServerProtocol: failed to marshall client's msg, " + e.Error())
	}
	if len(msg.Indexes) != 0 {
		for i := 0; i < len(msg.Indexes); i++ {
			temp, err := msg.Tags[i].MarshalBinary()
			if err != nil {
				return errors.New("ServerProtocol: failed to marshall tags, " + err.Error())
			}
			data = append(data, temp...)

			temp, err = msg.Proofs[i].ToBytes()
			if err != nil {
				return fmt.Errorf("error in proofs: %s", err)
			}
			data = append(data, temp...)

			data = append(data, []byte(strconv.Itoa(msg.Indexes[i]))...)

			err = SchnorrVerify(suite, Y[msg.Sigs[i].Index], data, msg.Sigs[i].Sig)
			if err != nil {
				return fmt.Errorf("error in signature: "+strconv.Itoa(i)+"\n%s", err)
			}
		}
	}

	//Check all the proofs
	if len(msg.Proofs) != 0 {
		for i, p := range msg.Proofs {
			var valid bool
			if p.R2 == nil {
				_, Y := context.Members()
				valid = verifyMisbehavingProof(suite, Y[i], &p, msg.Request.SCommits[0])
			} else {
				valid = verifyServerProof(suite, context, i, msg)
			}
			if !valid {
				return fmt.Errorf("invalid server proof")
			}
		}
	}

	//Step 2: Verify the correct behaviour of the client
	hasher := suite.Hash()
	suite.Point().Mul(server.PrivateKey(), msg.Request.SCommits[0]).MarshalTo(hasher)
	s := suite.Scalar().SetBytes(hasher.Sum(nil))
	var T kyber.Point
	var proof *ServerProof
	//Detect a misbehaving client and generate the elements of the server's message accordingly
	if !msg.Request.SCommits[server.Index()+2].Equal(suite.Point().Mul(s, msg.Request.SCommits[server.Index()+1])) {
		T = suite.Point().Null()
		proof, e = generateMisbehavingProof(suite, msg.Request.SCommits[0], server)
	} else {
		inv := suite.Scalar().Inv(s)
		exp := suite.Scalar().Mul(server.RoundSecret(), inv)
		if len(msg.Tags) == 0 {
			T = suite.Point().Mul(exp, msg.Request.T0)
		} else {
			T = suite.Point().Mul(exp, msg.Tags[len(msg.Tags)-1])
		}
		proof, e = generateServerProof(suite, context, s, T, msg, server)
	}
	if e != nil {
		return e
	}

	//Signs our message // FIXME QUESTION AGAIN ?? to me this thing has nothing to do here (and guess that it is/should be handled by Onet (TLS) or ??)
	temp, e := T.MarshalBinary()
	if e != nil {
		return fmt.Errorf("error in T: %s", e)
	}
	data = append(data, temp...)

	temp, e = proof.ToBytes()
	if e != nil {
		return fmt.Errorf("error in proof: %s", e)
	}
	data = append(data, temp...)

	data = append(data, []byte(strconv.Itoa(server.Index()))...)

	sign, e := SchnorrSign(suite, server.PrivateKey(), data)
	if e != nil {
		return fmt.Errorf("error in own signature: %s", e)
	}

	signature := ServerSignature{Sig: sign, Index: server.Index()}

	//Step 4: Form the new message
	msg.Tags = append(msg.Tags, T)
	msg.Proofs = append(msg.Proofs, *proof)
	msg.Indexes = append(msg.Indexes, server.Index())
	msg.Sigs = append(msg.Sigs, signature)

	return nil
}

/*generateServerProof creates the server proof for its computations*/
func generateServerProof(suite Suite, context AuthenticationContext, s kyber.Scalar, T kyber.Point, msg *ServerMessage, server Server) (proof *ServerProof, err error) {
	//Input validation
	if context == nil {
		return nil, fmt.Errorf("empty context")
	}
	if s == nil {
		return nil, fmt.Errorf("empty s")
	}
	if T == nil {
		return nil, fmt.Errorf("empty T")
	}
	if msg == nil {
		return nil, fmt.Errorf("empty server message")
	}

	//Step 1
	v1 := suite.Scalar().Pick(suite.RandomStream())
	v2 := suite.Scalar().Pick(suite.RandomStream())

	var a kyber.Point
	if len(msg.Tags) == 0 {
		a = suite.Point().Mul(v1, msg.Request.T0)
	} else {
		a = suite.Point().Mul(v1, msg.Tags[len(msg.Tags)-1])
	}

	//exp := suite.Scalar().Neg(v2)
	b := suite.Point().Mul(v2, T)
	t1 := suite.Point().Sub(a, b)

	t2 := suite.Point().Mul(v1, nil)

	t3 := suite.Point().Mul(v2, msg.Request.SCommits[server.Index()+1]) //Accesses S[j-1]

	//Step 2
	var Tprevious kyber.Point
	if len(msg.Tags) == 0 {
		Tprevious = msg.Request.T0
	} else {
		Tprevious = msg.Tags[len(msg.Tags)-1]
	}
	//Generating the hash
	hasher := suite.Hash()
	Tprevious.MarshalTo(hasher)
	T.MarshalTo(hasher)
	context.ServersSecretsCommitments()[server.Index()].MarshalTo(hasher)
	suite.Point().Mul(suite.Scalar().One(), nil).MarshalTo(hasher)
	msg.Request.SCommits[server.Index()+2].MarshalTo(hasher)
	msg.Request.SCommits[server.Index()+1].MarshalTo(hasher)
	t1.MarshalTo(hasher)
	t2.MarshalTo(hasher)
	t3.MarshalTo(hasher)
	challenge := hasher.Sum(nil)
	c := suite.Scalar().SetBytes(challenge)
	//rand := suite.Cipher(challenge)
	//c := suite.Scalar().Pick(rand)
	//Step 3
	d := suite.Scalar().Mul(c, server.RoundSecret())
	r1 := suite.Scalar().Sub(v1, d)

	e := suite.Scalar().Mul(c, s)
	r2 := suite.Scalar().Sub(v2, e)

	//Step 4
	return &ServerProof{
		T1: t1,
		T2: t2,
		T3: t3,
		C:  c,
		R1: r1,
		R2: r2,
	}, nil
}

/*verifyServerProof verifies a server proof*/
func verifyServerProof(suite Suite, context AuthenticationContext, i int, msg *ServerMessage) bool {
	//Input checks
	if context == nil || msg == nil {
		return false
	}

	if i >= len(msg.Proofs) || i < 0 {
		return false
	}

	//Verify format of the proof
	if msg.Proofs[i].C == nil || msg.Proofs[i].T1 == nil || msg.Proofs[i].T2 == nil || msg.Proofs[i].T3 == nil || msg.Proofs[i].R1 == nil || msg.Proofs[i].R2 == nil {
		return false
	}

	index := msg.Indexes[i]

	//Step 1
	var a kyber.Point
	if i == 0 {
		a = suite.Point().Mul(msg.Proofs[i].R1, msg.Request.T0)
	} else {
		a = suite.Point().Mul(msg.Proofs[i].R1, msg.Tags[i-1])
	}
	//exp := suite.Scalar().Neg(msg.proofs[i].r2)
	b := suite.Point().Mul(msg.Proofs[i].R2, msg.Tags[i])
	t1 := suite.Point().Sub(a, b)

	d := suite.Point().Mul(msg.Proofs[i].R1, nil)
	e := suite.Point().Mul(msg.Proofs[i].C, context.ServersSecretsCommitments()[index])
	t2 := suite.Point().Add(d, e)

	f := suite.Point().Mul(msg.Proofs[i].R2, msg.Request.SCommits[index+1])
	g := suite.Point().Mul(msg.Proofs[i].C, msg.Request.SCommits[index+2])
	t3 := suite.Point().Add(f, g)

	//Step 2
	var Tprevious kyber.Point
	if i == 0 {
		Tprevious = msg.Request.T0
	} else {
		Tprevious = msg.Tags[i-1]
	}
	// FIXME remember to use hashtwo when/where needed to keep things compatible with other implementations
	hasher := suite.Hash()
	Tprevious.MarshalTo(hasher)
	msg.Tags[i].MarshalTo(hasher)
	context.ServersSecretsCommitments()[index].MarshalTo(hasher)
	suite.Point().Mul(suite.Scalar().One(), nil).MarshalTo(hasher)
	msg.Request.SCommits[index+2].MarshalTo(hasher)
	msg.Request.SCommits[index+1].MarshalTo(hasher)
	t1.MarshalTo(hasher)
	t2.MarshalTo(hasher)
	t3.MarshalTo(hasher)
	challenge := hasher.Sum(nil)

	c := suite.Scalar().SetBytes(challenge)

	if !c.Equal(msg.Proofs[i].C) {
		return false
	}

	return true
}

/*generateMisbehavingProof creates the proof of a misbehaving client*/ // QUESTION server ? purpose of comment ?
func generateMisbehavingProof(suite Suite, Z kyber.Point, server Server) (proof *ServerProof, err error) {
	//Input checks
	if Z == nil {
		return nil, fmt.Errorf("empty Z")
	}

	Zs := suite.Point().Mul(server.PrivateKey(), Z)

	//Step 1
	v := suite.Scalar().Pick(suite.RandomStream())
	t1 := suite.Point().Mul(v, Z)
	t2 := suite.Point().Mul(v, nil)

	//Step 2
	hasher := sha512.New()
	var writer io.Writer = hasher
	Zs.MarshalTo(writer)
	Z.MarshalTo(writer)
	server.PublicKey().MarshalTo(writer)
	suite.Point().Mul(suite.Scalar().One(), nil).MarshalTo(writer)
	t1.MarshalTo(writer)
	t2.MarshalTo(writer)
	challenge := hasher.Sum(nil)

	hasher = suite.Hash()
	hasher.Write(challenge)
	//rand := suite.Cipher(challenge)
	c := suite.Scalar().SetBytes(hasher.Sum(nil))

	//Step 3
	a := suite.Scalar().Mul(c, server.PrivateKey())
	r := suite.Scalar().Sub(v, a)

	//Step 4
	return &ServerProof{
		T1: t1,
		T2: t2,
		T3: Zs,
		C:  c,
		R1: r,
		R2: nil,
	}, nil
}

/*verifyMisbehavingProof verifies a proof of a misbehaving client*/ // QUESTION server ? ..
func verifyMisbehavingProof(suite Suite, serverPublicKey kyber.Point, proof *ServerProof, Z kyber.Point) bool {
	//Input checks
	if serverPublicKey == nil || proof == nil || Z == nil {
		return false
	}

	//Check that this is a misbehaving proof
	if proof.R2 != nil {
		return false
	}

	//Verify format of the proof
	if proof.T1 == nil || proof.T2 == nil || proof.T3 == nil || proof.C == nil || proof.R1 == nil {
		return false
	}

	//Step 1
	a := suite.Point().Mul(proof.R1, Z)       //r1 = r
	b := suite.Point().Mul(proof.C, proof.T3) //t3 = Zs
	t1 := suite.Point().Add(a, b)

	d := suite.Point().Mul(proof.R1, nil) //r1 = r
	e := suite.Point().Mul(proof.C, serverPublicKey)
	t2 := suite.Point().Add(d, e)

	//Step 2
	hasher := sha512.New()
	var writer io.Writer = hasher
	proof.T3.MarshalTo(writer)
	Z.MarshalTo(writer)
	serverPublicKey.MarshalTo(writer)
	suite.Point().Mul(suite.Scalar().One(), nil).MarshalTo(writer)
	t1.MarshalTo(writer)
	t2.MarshalTo(writer)
	challenge := hasher.Sum(nil)

	hasher = suite.Hash()
	hasher.Write(challenge)

	//rand := suite.Cipher(challhasenge)
	c := suite.Scalar().SetBytes(hasher.Sum(nil))

	if !c.Equal(proof.C) {
		return false
	}
	return true
}

/*ToBytes is a helper function used to convert a ServerProof into []byte to be used in signatures*/
// QUESTION WTF ? + DRY there should be another way or no ?
func (proof ServerProof) ToBytes() (data []byte, err error) {
	temp, e := proof.T1.MarshalBinary()
	if e != nil {
		return nil, fmt.Errorf("error in t1: %s", e)
	}
	data = append(data, temp...)

	temp, e = proof.T2.MarshalBinary()
	if e != nil {
		return nil, fmt.Errorf("error in t2: %s", e)
	}
	data = append(data, temp...)

	temp, e = proof.T3.MarshalBinary()
	if e != nil {
		return nil, fmt.Errorf("error in t3: %s", e)
	}
	data = append(data, temp...)

	temp, e = proof.C.MarshalBinary()
	if e != nil {
		return nil, fmt.Errorf("error in c: %s", e)
	}
	data = append(data, temp...)

	temp, e = proof.R1.MarshalBinary()
	if e != nil {
		return nil, fmt.Errorf("error in r1: %s", e)
	}
	data = append(data, temp...)

	//Need to test if r2 == nil (Misbehaving)
	if proof.R2 != nil {
		temp, e = proof.R2.MarshalBinary()
		if e != nil {
			return nil, fmt.Errorf("error in r2: %s", e)
		}
		data = append(data, temp...)
	}

	return data, nil
}

/*GenerateNewRoundSecret creates a new secret for the server.
It returns the commitment to that secret to be included in the context and the new server*/
func GenerateNewRoundSecret(suite Suite, server Server) (kyber.Point, Server) {
	// FIXME rethink + instead store kp in server
	kp := key.NewKeyPair(suite)
	server.SetRoundSecret(kp.Private)
	return kp.Public, server
}
