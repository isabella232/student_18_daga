package daga
// TODO consider moving the tests in another package (blackbox testing) sub-directory daga_tests

import (
	"github.com/dedis/kyber"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"testing"
)

// FIXME review/see if the test are sound and correctly written
func TestNewClient(t *testing.T) {
	//Normal execution
	i := rand.Int()
	s := suite.Scalar().Pick(suite.RandomStream())
	client, err := NewClient(i, s)
	if err != nil || client.index != i || !client.key.Private.Equal(s) {
		t.Error("Cannot initialize a new client with a given private key")
	}

	client, err = NewClient(i, nil)
	if err != nil {
		t.Error("Cannot create a new client without a private key")
	}

	//Invalid input
	client, err = NewClient(-2, s)
	if err == nil {
		t.Error("Wrong check: Invalid index")
	}
}

func TestNewInitialTagAndCommitments(t *testing.T) {
	clients, servers, context, _ := generateTestContext(rand.Intn(10)+1, rand.Intn(10)+1)
	tagAndCommitments, s, err := newInitialTagAndCommitments(context.g.y, context.h[clients[0].index])

	T0, S := tagAndCommitments.t0, tagAndCommitments.sCommits
	if err != nil {
		assert.Equal(t, T0, nil, "T0 not nil on error")
		assert.Equal(t, S, nil, "S not nil on error")
		assert.Equal(t, s, nil, "s not nil on error")
		t.Error("Cannot create tag and commitments under regular context")
	}

	if T0 == nil {
		t.Error("T0 empty")
	}
	if T0.Equal(suite.Point().Null()) {
		t.Error("T0 is the null point")
	}

	if S == nil {
		t.Error("S is empty")
	}
	if len(S) != len(servers)+2 {
		t.Errorf("S has the wrong length: %d instead of %d", len(S), len(servers)+2)
	}
	for i, temp := range S {
		if temp.Equal(suite.Point().Null()) {
			t.Errorf("Null point in S at position %d", i)
		}
	}
	if s == nil {
		t.Error("s is empty")
	}
}

func newTestClientProof(client Client, context authenticationContext,
						tagAndCommitments initialTagAndCommitments, s kyber.Scalar) (clientProof, error){
	// TODO accept challenge as parameter

	// dummy channel to receive the commitments (they will be part of the returned proof)
	// and dummy channel to send a dummy challenge as we are only interested in the commitments
	// "push"/"pull" from the perspective of newClientProof()
	pushCommitments := make(chan []kyber.Point)
	pullChallenge := make(chan kyber.Scalar)
	go func() {
		<- pushCommitments
		// TODO sign challenge
		pullChallenge <- suite.Scalar().Pick(suite.RandomStream())
	}()

	return newClientProof(context, client, tagAndCommitments, s, pushCommitments, pullChallenge)
}

func TestNewClientProof(t *testing.T) {
	clients, _, context, _ := generateTestContext(rand.Intn(10)+1, rand.Intn(10)+1)
	// test for client 0
	tagAndCommitments, s, err := newInitialTagAndCommitments(context.g.y, context.h[clients[0].index])
	proof, err := newTestClientProof(clients[0], *context, *tagAndCommitments, s)
	if err != nil {
		t.Error("newClientProof returned an error:", err)
	}
	commits, responses, subChallenges:= proof.t, proof.r, proof.c
	// FIXME not sure whether these tests are pertinent or well written... they are testing the proof framework...not my code
	assert.Equal(t, len(commits), 3*len(clients))
	assert.Equal(t, len(subChallenges), len(clients))
	assert.Equal(t, len(responses), 2*len(clients))

	// TODO FIXME "port" these tests to the new implementation when everything related to challenge signatures is implemented
	////Incorrect challenges
	//var fake kyber.Scalar
	//for {
	//	fake = suite.Scalar().Pick(suite.RandomStream())
	//	if !fake.Equal(cs) {
	//		break
	//	}
	//}
	//wrongChallenge := Challenge{cs: fake, sigs: sigs}
	//c, r, err = clients[0].GenerateProofResponses(context, s, &wrongChallenge, v, w)
	//if err == nil {
	//	t.Error("Cannot verify the message")
	//}
	//if c != nil {
	//	t.Error("c not nil on message error")
	//}
	//if r != nil {
	//	t.Error("r not nil on message error")
	//}
	//
	////Signature modification
	//newsig := append([]byte("A"), sigs[0].sig...)
	//newsig = newsig[:len(sigs[0].sig)]
	//sigs[0].sig = newsig
	//SigChallenge := Challenge{cs: cs, sigs: sigs}
	//c, r, err = clients[0].GenerateProofResponses(context, s, &SigChallenge, v, w)
	//if err == nil {
	//	t.Error("Cannot verify the message")
	//}
	//if c != nil {
	//	t.Error("c not nil on signature error")
	//}
	//if r != nil {
	//	t.Error("r not nil on signature error")
	//}
}

func TestVerifyClientProof(t *testing.T) {
	clients, _, context, _ := generateTestContext(rand.Intn(10)+1, rand.Intn(10)+1)
	tagAndCommitments, s, _ := newInitialTagAndCommitments(context.g.y, context.h[clients[0].index])
	proof, _ := newTestClientProof(clients[0], *context, *tagAndCommitments, s)

	clientMsg := authenticationMessage{
		c: *context,
		initialTagAndCommitments: *tagAndCommitments,
		p0:  proof,
	}

	//Normal execution
	assert.True(t, ValidateClientMessage(&clientMsg), "Cannot validate client message")
	assert.True(t, verifyClientProof(clientMsg.c, clientMsg.p0, clientMsg.initialTagAndCommitments), "Cannot verify client proof")
	// redondant but for coverage and completeness
	assert.True(t, verifyAuthenticationMessage(clientMsg))

	//Modify the value of some commitments
	scratchMsg := clientMsg
	i := rand.Intn(len(clients))
	ttemp := scratchMsg.p0.t[3*i].Clone()
	scratchMsg.p0.t[3*i] = suite.Point().Null()
	assert.False(t, verifyAuthenticationMessage(scratchMsg), "Incorrect check of t at index %d", 3*i)

	scratchMsg.p0.t[3*i] = ttemp.Clone()
	ttemp = scratchMsg.p0.t[3*i+1].Clone()
	scratchMsg.p0.t[3*i+1] = suite.Point().Null()
	assert.False(t, verifyAuthenticationMessage(scratchMsg), "Incorrect check of t at index %d", 3*i+1)

	scratchMsg.p0.t[3*i+1] = ttemp.Clone()
	ttemp = scratchMsg.p0.t[3*i+2].Clone()
	scratchMsg.p0.t[3*i+2] = suite.Point().Null()
	assert.False(t, verifyAuthenticationMessage(scratchMsg), "Incorrect check of t at index %d", 3*i+2)

	scratchMsg.p0.t[3*i+2] = ttemp.Clone()

	//Modify the value of the challenge
	scratchMsg.p0.cs = suite.Scalar().Zero()
	assert.False(t, verifyAuthenticationMessage(scratchMsg), "Incorrect check of the challenge")
}


// TODO will become kind of a TestnewAuthenticationMessage
//func TestAssembleMessage(t *testing.T) {
//	clients, servers, context, _ := generateTestContext(rand.Intn(10)+1, rand.Intn(10)+1)
//	tagAndCommitments, s, _ := newInitialTagAndCommitments(context.g.y, context.h[clients[0].index])
//	T0, S := tagAndCommitments.t0, tagAndCommitments.sCommits
//	tclient, v, w := clients[0].GenerateProofCommitments(context, T0, s)
//
//	//Dumb challenge generation
//	cs := suite.Scalar().Pick(suite.RandomStream())
//	msg, _ := cs.MarshalBinary()
//	var sigs []serverSignature
//	//Make each test server sign the challenge
//	for _, server := range servers {
//		sig, e := ECDSASign(server.private, msg)
//		if e != nil {
//			t.Errorf("Cannot sign the challenge for server %d", server.index)
//		}
//		sigs = append(sigs, serverSignature{index: server.index, sig: sig})
//	}
//	challenge := Challenge{cs: cs, sigs: sigs}
//
//	c, r, _ := clients[0].GenerateProofResponses(context, s, &challenge, v, w)
//
//	//Normal execution
//	clientMsg := clients[0].AssembleMessage(context, &S, T0, &challenge, tclient, c, r)
//	if !ValidateClientMessage(clientMsg) || clientMsg == nil {
//		t.Error("Cannot assemble a client message")
//	}
//
//	//Empty inputs
//	clientMsg = clients[0].AssembleMessage(nil, &S, T0, &challenge, tclient, c, r)
//	if clientMsg != nil {
//		t.Error("Wrong check: Empty context")
//	}
//	clientMsg = clients[0].AssembleMessage(context, nil, T0, &challenge, tclient, c, r)
//	if clientMsg != nil {
//		t.Error("Wrong check: Empty S")
//	}
//	clientMsg = clients[0].AssembleMessage(context, &[]kyber.Point{}, T0, &challenge, tclient, c, r)
//	if clientMsg != nil {
//		t.Error("Wrong check: len(S) = 0")
//	}
//	clientMsg = clients[0].AssembleMessage(context, &S, nil, &challenge, tclient, c, r)
//	if clientMsg != nil {
//		t.Error("Wrong check: Empty T0")
//	}
//	clientMsg = clients[0].AssembleMessage(context, &S, T0, nil, tclient, c, r)
//	if clientMsg != nil {
//		t.Error("Wrong check: Empty challenge")
//	}
//	clientMsg = clients[0].AssembleMessage(context, &S, T0, &challenge, nil, c, r)
//	if clientMsg != nil {
//		t.Error("Wrong check: Empty t")
//	}
//	clientMsg = clients[0].AssembleMessage(context, &S, T0, &challenge, &[]kyber.Point{}, c, r)
//	if clientMsg != nil {
//		t.Error("Wrong check: len(t) = 0 ")
//	}
//	clientMsg = clients[0].AssembleMessage(context, &S, T0, &challenge, tclient, nil, r)
//	if clientMsg != nil {
//		t.Error("Wrong check: Empty c")
//	}
//	clientMsg = clients[0].AssembleMessage(context, &S, T0, &challenge, tclient, &[]kyber.Scalar{}, r)
//	if clientMsg != nil {
//		t.Error("Wrong check: Empty ")
//	}
//	clientMsg = clients[0].AssembleMessage(context, &S, T0, &challenge, tclient, c, nil)
//	if clientMsg != nil {
//		t.Error("Wrong check: Empty r")
//	}
//	clientMsg = clients[0].AssembleMessage(context, &S, T0, &challenge, tclient, c, &[]kyber.Scalar{})
//	if clientMsg != nil {
//		t.Error("Wrong check: Empty ")
//	}
//
//}

//func TestGetFinalLinkageTag(t *testing.T) {
//	clients, servers, context, _ := generateTestContext(1, 2)
//	for _, server := range servers {
//		if server.r == nil {
//			t.Errorf("Error in r for server %d", server.index)
//		}
//	}
//	T0, S, s, _ := clients[0].CreateRequest(context)
//	tclient, v, w := clients[0].GenerateProofCommitments(context, T0, s)
//
//	//Dumb challenge generation
//	cs := suite.Scalar().Pick(suite.RandomStream())
//	msg, _ := cs.MarshalBinary()
//	var sigs []serverSignature
//	//Make each test server sign the challenge
//	for _, server := range servers {
//		sig, e := ECDSASign(server.private, msg)
//		if e != nil {
//			t.Errorf("Cannot sign the challenge for server %d", server.index)
//		}
//		sigs = append(sigs, serverSignature{index: server.index, sig: sig})
//	}
//	challenge := Challenge{cs: cs, sigs: sigs}
//
//	c, r, _ := clients[0].GenerateProofResponses(context, s, &challenge, v, w)
//
//	//Assemble the client message
//	clientMessage := ClientMessage{sArray: S, t0: T0, context: *context,
//		proof: ClientProof{cs: cs, c: *c, t: *tclient, r: *r}}
//
//	//Create the initial server message
//	servMsg := ServerMessage{request: clientMessage, proofs: nil, tags: nil, sigs: nil, indexes: nil}
//
//	//Run ServerProtocol on each server
//	for i := range servers {
//		servers[i].ServerProtocol(context, &servMsg)
//	}
//
//	//Normal execution for a normal client
//	Tf, err := clients[0].GetFinalLinkageTag(context, &servMsg)
//	if err != nil || Tf == nil {
//		t.Errorf("Cannot extract final linkage tag:\n%s", err)
//	}
//
//	//Empty inputs
//	Tf, err = clients[0].GetFinalLinkageTag(nil, &servMsg)
//	if err == nil || Tf != nil {
//		t.Errorf("Wrong check: Empty context")
//	}
//	Tf, err = clients[0].GetFinalLinkageTag(context, nil)
//	if err == nil || Tf != nil {
//		t.Errorf("Wrong check: Empty message")
//	}
//
//	//Change a signature
//	servMsg.sigs[0].sig = append(servMsg.sigs[0].sig[1:], servMsg.sigs[0].sig[0])
//	Tf, err = clients[0].GetFinalLinkageTag(context, &servMsg)
//	if err == nil || Tf != nil {
//		t.Errorf("Invalid signature accepted")
//	}
//	//Revert the change
//	servMsg.sigs[0].sig = append([]byte{0x0}, servMsg.sigs[0].sig...)
//	servMsg.sigs[0].sig[0] = servMsg.sigs[0].sig[len(servMsg.sigs[0].sig)-1]
//	servMsg.sigs[0].sig = servMsg.sigs[0].sig[:len(servMsg.sigs[0].sig)-2]
//
//	//Normal execution for a misbehaving client
//	//Assemble the client message
//	S[2] = suite.Point().Null()
//	clientMessage = ClientMessage{sArray: S, t0: T0, context: *context,
//		proof: ClientProof{cs: cs, c: *c, t: *tclient, r: *r}}
//
//	//Create the initial server message
//	servMsg = ServerMessage{request: clientMessage, proofs: nil, tags: nil, sigs: nil, indexes: nil}
//
//	//Run ServerProtocol on each server
//	for i := range servers {
//		servers[i].ServerProtocol(context, &servMsg)
//	}
//	Tf, err = clients[0].GetFinalLinkageTag(context, &servMsg)
//	if err != nil {
//		t.Errorf("Cannot extract final linkage tag for a misbehaving client")
//	}
//	if !Tf.Equal(suite.Point().Null()) {
//		t.Error("Tf not Null for a misbehaving client")
//	}
//}
//
//func TestValidateClientMessage(t *testing.T) {
//	clients, servers, context, _ := generateTestContext(rand.Intn(10)+1, rand.Intn(10)+1)
//	T0, S, s, _ := clients[0].CreateRequest(context)
//	tproof, v, w := clients[0].GenerateProofCommitments(context, T0, s)
//
//	//Dumb challenge generation
//	cs := suite.Scalar().Pick(suite.RandomStream())
//	msg, _ := cs.MarshalBinary()
//	var sigs []serverSignature
//	//Make each test server sign the challenge
//	for _, server := range servers {
//		sig, e := ECDSASign(server.private, msg)
//		if e != nil {
//			t.Errorf("Cannot sign the challenge for server %d", server.index)
//		}
//		sigs = append(sigs, serverSignature{index: server.index, sig: sig})
//	}
//	challenge := Challenge{cs: cs, sigs: sigs}
//
//	//Generate the final proof
//	c, r, _ := clients[0].GenerateProofResponses(context, s, &challenge, v, w)
//
//	ClientMsg := ClientMessage{context: ContextEd25519{G: Members{X: context.G.X, Y: context.G.Y}, R: context.R, H: context.H},
//		t0:     T0,
//		sArray: S,
//		proof:  ClientProof{c: *c, cs: cs, r: *r, t: *tproof}}
//
//	//Normal execution
//	check := verifyClientProof(ClientMsg)
//	if !check {
//		t.Error("Cannot verify client proof")
//	}
//
//	//Modifying the length of various elements
//	ScratchMsg := ClientMsg
//	ScratchMsg.p0.c = append(ScratchMsg.p0.c, suite.Scalar().Pick(suite.RandomStream()))
//	check = verifyClientProof(ScratchMsg)
//	if check {
//		t.Errorf("Incorrect length check for c: %d instead of %d", len(ScratchMsg.p0.c), len(clients))
//	}
//	ScratchMsg.p0.c = ScratchMsg.p0.c[:len(clients)-1]
//	check = verifyClientProof(ScratchMsg)
//	if check {
//		t.Errorf("Incorrect length check for c: %d instead of %d", len(ScratchMsg.p0.c), len(clients))
//	}
//
//	ScratchMsg = ClientMsg
//	ScratchMsg.p0.r = append(ScratchMsg.p0.r, suite.Scalar().Pick(suite.RandomStream()))
//	check = verifyClientProof(ScratchMsg)
//	if check {
//		t.Errorf("Incorrect length check for r: %d instead of %d", len(ScratchMsg.p0.c), len(clients))
//	}
//	ScratchMsg.p0.r = ScratchMsg.p0.r[:2*len(clients)-1]
//	check = verifyClientProof(ScratchMsg)
//	if check {
//		t.Errorf("Incorrect length check for r: %d instead of %d", len(ScratchMsg.p0.c), len(clients))
//	}
//
//	ScratchMsg = ClientMsg
//	ScratchMsg.p0.t = append(ScratchMsg.p0.t, suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil))
//	check = verifyClientProof(ScratchMsg)
//	if check {
//		t.Errorf("Incorrect length check for t: %d instead of %d", len(ScratchMsg.p0.c), len(clients))
//	}
//	ScratchMsg.p0.t = ScratchMsg.p0.t[:3*len(clients)-1]
//	check = verifyClientProof(ScratchMsg)
//	if check {
//		t.Errorf("Incorrect length check for t: %d instead of %d", len(ScratchMsg.p0.c), len(clients))
//	}
//
//	ScratchMsg = ClientMsg
//	ScratchMsg.sArray = append(ScratchMsg.sArray, suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil))
//	check = verifyClientProof(ScratchMsg)
//	if check {
//		t.Errorf("Incorrect length check for S: %d instead of %d", len(ScratchMsg.sArray), len(servers)+2)
//	}
//	ScratchMsg.sArray = ScratchMsg.sArray[:len(servers)+1]
//	check = verifyClientProof(ScratchMsg)
//	if check {
//		t.Errorf("Incorrect length check for S: %d instead of %d", len(ScratchMsg.sArray), len(servers)+2)
//	}
//
//	//Modify the value of the generator in S[1]
//	ScratchMsg = ClientMsg
//	ScratchMsg.sArray[1] = suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)
//	check = verifyClientProof(ScratchMsg)
//	if check {
//		t.Errorf("Incorrect check for the generator in S[1]")
//	}
//	ScratchMsg.sArray[1] = suite.Point().Mul(suite.Scalar().One(), nil)
//
//	//Remove T0
//	ScratchMsg.t0 = nil
//	check = verifyClientProof(ScratchMsg)
//	if check {
//		t.Errorf("Accepts a empty T0")
//	}
//}
//
//func TestToBytes_ClientMessage(t *testing.T) {
//	clients, servers, context, _ := generateTestContext(rand.Intn(10)+1, rand.Intn(10)+1)
//	T0, S, s, _ := clients[0].CreateRequest(context)
//	tproof, v, w := clients[0].GenerateProofCommitments(context, T0, s)
//
//	//Dumb challenge generation
//	cs := suite.Scalar().Pick(suite.RandomStream())
//	msg, _ := cs.MarshalBinary()
//	var sigs []serverSignature
//	//Make each test server sign the challenge
//	for _, server := range servers {
//		sig, e := ECDSASign(server.private, msg)
//		if e != nil {
//			t.Errorf("Cannot sign the challenge for server %d", server.index)
//		}
//		sigs = append(sigs, serverSignature{index: server.index, sig: sig})
//	}
//	challenge := Challenge{cs: cs, sigs: sigs}
//
//	//Generate the final proof
//	c, r, _ := clients[0].GenerateProofResponses(context, s, &challenge, v, w)
//
//	ClientMsg := ClientMessage{context: ContextEd25519{G: Members{X: context.G.X, Y: context.G.Y}, R: context.R, H: context.H},
//		t0:     T0,
//		sArray: S,
//		proof:  ClientProof{c: *c, cs: cs, r: *r, t: *tproof}}
//
//	//Normal execution
//	data, err := ClientMsg.ToBytes()
//	if err != nil {
//		t.Error("Cannot convert valid Client Message to bytes")
//	}
//	if data == nil {
//		t.Error("Data is empty for a correct Client Message")
//	}
//}
//
//func TestToBytes_ClientProof(t *testing.T) {
//	clients, servers, context, _ := generateTestContext(rand.Intn(10)+1, rand.Intn(10)+1)
//	T0, _, s, _ := clients[0].CreateRequest(context)
//	tproof, v, w := clients[0].GenerateProofCommitments(context, T0, s)
//
//	//Dumb challenge generation
//	cs := suite.Scalar().Pick(suite.RandomStream())
//	msg, _ := cs.MarshalBinary()
//	var sigs []serverSignature
//	//Make each test server sign the challenge
//	for _, server := range servers {
//		sig, e := ECDSASign(server.private, msg)
//		if e != nil {
//			t.Errorf("Cannot sign the challenge for server %d", server.index)
//		}
//		sigs = append(sigs, serverSignature{index: server.index, sig: sig})
//	}
//	challenge := Challenge{cs: cs, sigs: sigs}
//
//	//Generate the final proof
//	c, r, _ := clients[0].GenerateProofResponses(context, s, &challenge, v, w)
//
//	proof := clientProof{c: *c, cs: cs, r: *r, t: *tproof}
//
//	//Normal execution
//	data, err := proof.ToBytes()
//	if err != nil {
//		t.Error("Cannot convert valid proof to bytes")
//	}
//	if data == nil {
//		t.Error("Data is empty for a correct proof")
//	}
//}
