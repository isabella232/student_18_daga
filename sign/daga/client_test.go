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
	assert.NoError(t, err, "Cannot initialize a new client with a given private key")
	assert.Equal(t, i, client.index, "Cannot initialize a new client with a given private key, wrong index")
	assert.True(t, client.key.Private.Equal(s), "Cannot initialize a new client with a given private key, wrong key")

	client, err = NewClient(i, nil)
	assert.NoError(t, err, "Cannot create a new client without a private key")

	//Invalid input
	client, err = NewClient(-2, s)
	assert.Error(t, err, "Wrong check: Invalid index")
}

func TestNewInitialTagAndCommitments(t *testing.T) {
	clients, servers, context, _ := generateTestContext(rand.Intn(10)+2, rand.Intn(10)+2)

	// normal execution
	tagAndCommitments, s, err := newInitialTagAndCommitments(context.g.y, context.h[clients[0].index])
	T0, S := tagAndCommitments.t0, tagAndCommitments.sCommits
	assert.NoError(t, err, "Cannot create tag and commitments under regular context")
	assert.NotNil(t, T0, "no error but T0 nil")
	assert.NotNil(t, S, "no error but sCommits nil")
	assert.NotNil(t, s,"no error but s nil")
	assert.False(t, T0.Equal(suite.Point().Null()), "T0 is the null point")
	assert.Equal(t, len(S), len(servers)+2, "S has the wrong length: %d instead of %d", len(S), len(servers)+2)
	for i, temp := range S {
		assert.False(t, temp.Equal(suite.Point().Null()),"Null point in sCommits at position %d", i)
	}
}
// test helper that sign returns a Challenge by signing the cs using the keys of the servers
func signDummyChallenge(cs kyber.Scalar, servers []Server) Challenge {
	msg, _ := cs.MarshalBinary()
	var sigs []serverSignature
	//Make each test server sign the challenge
	for _, server := range servers {
		sig, _ := ECDSASign(server.private, msg)
		sigs = append(sigs, serverSignature{index: server.index, sig: sig})
	}
	return Challenge{cs: cs, sigs: sigs}
}

// test helper that returns dummy channels to act as a dummy server/verifier
// that send challenge on pullChallenge channel upon reception of the prover's commitments on pullChallenge channel
func newDummyServerChannels(challenge Challenge) (chan []kyber.Point, chan Challenge) {
	// dummy channel to receive the commitments (they will be part of the returned proof)
	// and dummy channel to send a dummy challenge as we are only interested in the commitments
	// "push"/"pull" from the perspective of newClientProof()
	pushCommitments := make(chan []kyber.Point)
	pullChallenge := make(chan Challenge)
	go func() {
		<- pushCommitments
		pullChallenge <- challenge
	}()
	return pushCommitments, pullChallenge
}

func TestNewClientProof(t *testing.T) {
	// setup, test context, clients, servers
	clients, servers, context, _ := generateTestContext(rand.Intn(10)+2, rand.Intn(10)+2)

	// setup dummy server "channels"
	cs := suite.Scalar().Pick(suite.RandomStream())
	validChallenge := signDummyChallenge(cs, servers)
	pushCommitments, pullChallenge := newDummyServerChannels(validChallenge)

	// normal execution, create client proof
	tagAndCommitments, s, err := newInitialTagAndCommitments(context.g.y, context.h[clients[0].index])
	proof, err := newClientProof(*context, clients[0], *tagAndCommitments, s, pushCommitments, pullChallenge)

	assert.NoError(t, err,"newClientProof returned an error on valid inputs")
	commits, responses, subChallenges:= proof.t, proof.r, proof.c
	// FIXME not sure whether these tests are pertinent or well written... they are testing the proof framework...not my code
	assert.Equal(t, len(commits), 3*len(clients))
	assert.Equal(t, len(subChallenges), len(clients))
	assert.Equal(t, len(responses), 2*len(clients))

	//Incorrect challenges
	var fake kyber.Scalar
	for {
		fake = suite.Scalar().Pick(suite.RandomStream())
		if !fake.Equal(cs) {
			break
		}
	}
	invalidChallenge := Challenge{cs: fake, sigs: validChallenge.sigs}
	pushCommitments, pullChallenge = newDummyServerChannels(invalidChallenge)
	proof, err = newClientProof(*context, clients[0], *tagAndCommitments, s, pushCommitments, pullChallenge)
	commits, responses, subChallenges = proof.t, proof.r, proof.c
	assert.Error(t, err,"newClientProof returned no error on invalid server inputs (altered challenge)")
	assert.Equal(t, clientProof{}, proof, "proof not \"zero\" on error")

	//Signature modification
	newsig := append(validChallenge.sigs[0].sig, []byte("A")...)
	newsig = newsig[1:]
	wrongSigs := make([]serverSignature, len(validChallenge.sigs))
	copy(wrongSigs, validChallenge.sigs)
	wrongSigs[0].sig = newsig
	invalidChallenge = Challenge{cs: cs, sigs: wrongSigs}
	pushCommitments, pullChallenge = newDummyServerChannels(invalidChallenge)

	proof, err = newClientProof(*context, clients[0], *tagAndCommitments, s, pushCommitments, pullChallenge)
	commits, responses, subChallenges = proof.t, proof.r, proof.c
	assert.Error(t, err,"newClientProof returned no error on invalid server inputs (altered signature)")
	assert.Equal(t, clientProof{}, proof, "proof not \"zero\" on error")
}

func TestVerifyClientProof(t *testing.T) {
	// setup, test context, clients, servers
	clients, servers, context, _ := generateTestContext(rand.Intn(10)+2, rand.Intn(10)+2)

	// setup dummy server "channels"
	cs := suite.Scalar().Pick(suite.RandomStream())
	validChallenge := signDummyChallenge(cs, servers)
	pushCommitments, pullChallenge := newDummyServerChannels(validChallenge)

	// create valid proof and auth. message
	tagAndCommitments, s, _ := newInitialTagAndCommitments(context.g.y, context.h[clients[0].index])
	proof, _ := newClientProof(*context, clients[0], *tagAndCommitments, s, pushCommitments, pullChallenge)

	clientMsg := authenticationMessage{
		c: *context,
		initialTagAndCommitments: *tagAndCommitments,
		p0:  proof,
	}

	//Normal execution
	assert.True(t, ValidateClientMessage(&clientMsg), "Cannot validate valid client message")
	assert.True(t, verifyAuthenticationMessage(clientMsg), "Cannot verify valid client proof")

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

	//tamper the challenge
	scratchMsg.p0.cs = suite.Scalar().Zero()
	assert.False(t, verifyAuthenticationMessage(scratchMsg), "Incorrect check of the challenge")
}

func TestGetFinalLinkageTag(t *testing.T) {
	// setup, test context, clients, servers, and "network channel"
	clients, servers, context, _ := generateTestContext(rand.Intn(10)+2, 1/*rand.Intn(10)+1*/)

	// setup dummy server "channels"
	cs := suite.Scalar().Pick(suite.RandomStream())
	validChallenge := signDummyChallenge(cs, servers)
	pushCommitments, pullChallenge := newDummyServerChannels(validChallenge)

	//Create test authMsg M0 // TODO instead of these (above and below tests too) use NewAuthMessage (=> make new Auth message easily testable by adding server channels parameters)
	tagAndCommitments, s, _ := newInitialTagAndCommitments(context.g.y, context.h[clients[0].index])
	proof, _ := newClientProof(*context, clients[0], *tagAndCommitments, s, pushCommitments, pullChallenge)
	clientMessage := authenticationMessage{
		c: *context,
		initialTagAndCommitments: *tagAndCommitments,
		p0:  proof,
	}

	//Create the initial server message
	servMsg := ServerMessage{request: clientMessage, proofs: nil, tags: nil, sigs: nil, indexes: nil}

	//Run ServerProtocol on each server
	for i := range servers {
		err := servers[i].ServerProtocol(context, &servMsg)
		assert.NoError(t, err, "server %v returned an error while processing valid auth. request", i)
	}

	//Normal execution for a normal client
	Tf, err := clients[0].GetFinalLinkageTag(context, &servMsg)
	assert.NoError(t, err, "Cannot extract final linkage tag")
	assert.NotNil(t, Tf, "Cannot extract final linkage tag")

	//Empty inputs
	Tf, err = clients[0].GetFinalLinkageTag(nil, &servMsg)
	assert.Error(t, err, "wrong check: Empty context")
	assert.Nil(t, Tf, "wrong check: Empty context")

	Tf, err = clients[0].GetFinalLinkageTag(context, nil)
	assert.Error(t, err, "wrong check: Empty context")
	assert.Nil(t, Tf, "wrong check: Empty context")

	//Change a signature
	servMsg.sigs[0].sig = append(servMsg.sigs[0].sig[1:], servMsg.sigs[0].sig[0])
	Tf, err = clients[0].GetFinalLinkageTag(context, &servMsg)
	assert.Error(t, err, "Invalid signature accepted")
	assert.Nil(t, Tf, "Invalid signature accepted")

	//Revert the change
	servMsg.sigs[0].sig = append([]byte{0x0}, servMsg.sigs[0].sig...)
	servMsg.sigs[0].sig[0] = servMsg.sigs[0].sig[len(servMsg.sigs[0].sig)-1]
	servMsg.sigs[0].sig = servMsg.sigs[0].sig[:len(servMsg.sigs[0].sig)-2]

	//Normal execution for a misbehaving client
	// TODO QUESTION make sense out of the following / see with Ewa Syta if I should implement the "expose misbehaving clients" extension
	//Assemble the client message
	S := tagAndCommitments.sCommits

	S[2] = suite.Point().Null()
	// FIXME HERE I Guess that the previous student forgot to regenerate the proof using the wrong commitments and wrong secret !
	// QUESTION : I was maybe a little hard with the previous student and this bug as it might be kind of a hole in the
	// QUESTION DAGA paper itself, because I currently don't see how a client can generate a proof s.t. both the proof is accepted and
	// QUESTION the client is flagged as misbehaving ..?
	// => I see this can be the case when number servers > 1, when number servers = 1 the proof is rejected
	// but we need to add another test case for a client that would send a request without knowing a shared secret with the server (= misbehaving)
	// (this would be stupid since every one can derive a shared secret with a server, but need to be sure that our code is correct even in this case)
	pushCommitments, pullChallenge = newDummyServerChannels(validChallenge)
	proof, _ = newClientProof(*context, clients[0], *tagAndCommitments, s, pushCommitments, pullChallenge)
	clientMessage = authenticationMessage{
		c: *context,
		initialTagAndCommitments: *tagAndCommitments,
		p0:  proof,
	}

	// FIXME understand why this final test segfault when running all tests but pass when running only this test
	// got it it was the state of the rand, when running only this one it was fine but when running all tests
	// the rand returned s=1, meaning only one server
	// => uncovered a hidden bug, + now ensure that there is at least 2 clients as in DAGA paper
	// TODO remains to understand why s=1 is ko, I guess that somewhere there is an hidden assumption that s>1
	// which is sound since if s=1 we are in a centralized setting and this is kind of out of the assumptions of the daga paper
	// which expressly state that there should be at least one honest server

	// ok got it, when more than one server the msg.tags not nil but when 1 server it is nil (AND wrong proof) and the
	// 	return msg.tags[len(msg.tags)-1]
	// has an index out of bound error !!
	// TODO remains to know how to fix it in a way that is DAGA compliant, anyway I guess that there are lots of such bugs hidden in the server code.. I lost trust in this code long ago
	// ok in fact this misbehaving client test is ~~utterly stupid~~(only when #server is 1, my apologies), by modifying the commits this will trigger the proof to be rejected by the Verifier
	// up to now ok, but on invalid proof the serverProtocol returns an error BEFORE doing anything related to misbehaving clients !! and BEFORE setting anything
	// in the tags slice => that is the very fundamental error and why the slice remains nil on s=1 AND misbehaving client
	// so here it is another bug in previous student code
	// QUESTION to Linus, are you still convinced I was wrong/lost time in vain while not listening on good advices ?
	// (allowing these bugs to hit me in the face while doing other things later and being convinced that everything works because the "tests" are passing...)
	// (by the way the tests ARE passing, as I told you just like the tests of previous student passed)
	// there is now plenty of evidences of fishy things (both on the correctness and on the quality of the code) that I exposed during these 2 weeks
	// (see the various QUESTION tag and wtfs and comments and notes)
	// QUESTION to Linus can you at least acknowledge them ? and maybe update your unfair judgment of monday ?
	// QUESTION to Linus should I continue my rewrite/audit or should I move on anyway ?

	//Create the initial server message
	servMsg = ServerMessage{
		request: clientMessage,
		proofs: nil,
		tags: nil,
		sigs: nil,
		indexes: nil,
	}

	//Run ServerProtocol on each server
	// QUESTION need to clarify with Ewa Syta what is the correct thing to do for this scenario
	for i := range servers {
		err := servers[i].ServerProtocol(context, &servMsg)
		assert.NoError(t, err, "server %v returned an error while processing auth. request of a misbehaving client", i)
	}
	Tf, err = clients[0].GetFinalLinkageTag(context, &servMsg)
	assert.NoError(t, err, "cannot extract final linkage tag for a misbehaving client")
	assert.True(t, Tf.Equal(suite.Point().Null()), "Tf not Null for a misbehaving client")
}

// TODO merge or rearrange with some tests above as lots of things are redundant...or should belong to same test
// e.g see testverifyclientproof and its tampering of the p0.commitments
// + fundamentaly verify message => verify proof, so either split accordingly and test only message related things reps. proof related things in both
// or merge them together in same test and test everything
// or (but I won't lose more time on this) rewrite everything to follow best testing practises (more better named small tests for a start)
func TestValidateClientMessage(t *testing.T) {
	// setup, test context, clients, servers, and "network channel"
	clients, servers, context, _ := generateTestContext(rand.Intn(10)+1, rand.Intn(10)+1)

	// setup dummy server "channels"
	cs := suite.Scalar().Pick(suite.RandomStream())
	validChallenge := signDummyChallenge(cs, servers)
	pushCommitments, pullChallenge := newDummyServerChannels(validChallenge)

	//Create test authMsg M0
	tagAndCommitments, s, _ := newInitialTagAndCommitments(context.g.y, context.h[clients[0].index])
	proof, _ := newClientProof(*context, clients[0], *tagAndCommitments, s, pushCommitments, pullChallenge)
	clientMessage := authenticationMessage{
		c: *context,
		initialTagAndCommitments: *tagAndCommitments,
		p0:  proof,
	}

	//Normal execution
	// TODO already tested somewhere above...
	assert.True(t, verifyAuthenticationMessage(clientMessage),"Cannot verify valid client proof")


	//Modifying the length of various elements
	ScratchMsg := clientMessage
	ScratchMsg.p0.c = append(ScratchMsg.p0.c, suite.Scalar().Pick(suite.RandomStream()))
	assert.False(t, verifyAuthenticationMessage(ScratchMsg), "Incorrect length check for c: %d instead of %d", len(ScratchMsg.p0.c), len(clients))

	ScratchMsg.p0.c = ScratchMsg.p0.c[:len(clients)-1]
	assert.False(t, verifyAuthenticationMessage(ScratchMsg), "Incorrect length check for c: %d instead of %d", len(ScratchMsg.p0.c), len(clients))

	ScratchMsg = clientMessage
	ScratchMsg.p0.r = append(ScratchMsg.p0.r, suite.Scalar().Pick(suite.RandomStream()))
	assert.False(t, verifyAuthenticationMessage(ScratchMsg), "Incorrect length check for r: %d instead of %d", len(ScratchMsg.p0.c), len(clients))

	ScratchMsg.p0.r = ScratchMsg.p0.r[:2*len(clients)-1]
	assert.False(t, verifyAuthenticationMessage(ScratchMsg), "Incorrect length check for r: %d instead of %d", len(ScratchMsg.p0.c), len(clients))

	ScratchMsg = clientMessage
	ScratchMsg.p0.t = append(ScratchMsg.p0.t, suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil))
	assert.False(t, verifyAuthenticationMessage(ScratchMsg), "Incorrect length check for t: %d instead of %d", len(ScratchMsg.p0.c), len(clients))

	ScratchMsg.p0.t = ScratchMsg.p0.t[:3*len(clients)-1]
	assert.False(t, verifyAuthenticationMessage(ScratchMsg), "Incorrect length check for t: %d instead of %d", len(ScratchMsg.p0.c), len(clients))

	ScratchMsg = clientMessage
	ScratchMsg.sCommits = append(ScratchMsg.sCommits, suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil))
	assert.False(t, verifyAuthenticationMessage(ScratchMsg), "Incorrect length check for S: %d instead of %d", len(ScratchMsg.sCommits), len(servers)+2)

	ScratchMsg.sCommits = ScratchMsg.sCommits[:len(servers)+1]
	assert.False(t, verifyAuthenticationMessage(ScratchMsg), "Incorrect length check for S: %d instead of %d", len(ScratchMsg.sCommits), len(servers)+2)

	//Modify the value of the generator in S[1]
	ScratchMsg = clientMessage
	ScratchMsg.sCommits[1] = suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)
	assert.False(t, verifyAuthenticationMessage(ScratchMsg), "Incorrect check for the generator in S[1]")

	ScratchMsg.sCommits[1] = suite.Point().Mul(suite.Scalar().One(), nil)

	//Remove T0
	ScratchMsg.t0 = nil
	assert.False(t, verifyAuthenticationMessage(ScratchMsg), "Accepts a empty T0")
}

func TestToBytes_ClientMessage(t *testing.T) {
	// setup, test context, clients, servers, and "network channel"
	clients, servers, context, _ := generateTestContext(rand.Intn(10)+2, rand.Intn(10)+1)

	// setup dummy server "channels"
	cs := suite.Scalar().Pick(suite.RandomStream())
	validChallenge := signDummyChallenge(cs, servers)
	pushCommitments, pullChallenge := newDummyServerChannels(validChallenge)

	//Create test authMsg M0  // TODO instead of these (above and below tests too) use NewAuthMessage (=> make new Auth message easily testable by adding server channels parameters)
	tagAndCommitments, s, _ := newInitialTagAndCommitments(context.g.y, context.h[clients[0].index])
	proof, _ := newClientProof(*context, clients[0], *tagAndCommitments, s, pushCommitments, pullChallenge)
	clientMessage := authenticationMessage{
		c: *context,
		initialTagAndCommitments: *tagAndCommitments,
		p0:  proof,
	}

	//Normal execution
	data, err := clientMessage.ToBytes()
	assert.NoError(t, err,"Cannot convert valid Client Message to bytes")
	assert.NotNil(t, data,"Data is empty for a correct Client Message")
}

func TestToBytes_ClientProof(t *testing.T) {
	// setup, test context, clients, servers, and "network channel"
	clients, servers, context, _ := generateTestContext(rand.Intn(10)+2, rand.Intn(10)+1)

	// setup dummy server "channels"
	cs := suite.Scalar().Pick(suite.RandomStream())
	validChallenge := signDummyChallenge(cs, servers)
	pushCommitments, pullChallenge := newDummyServerChannels(validChallenge)

	//Create test client proof
	tagAndCommitments, s, _ := newInitialTagAndCommitments(context.g.y, context.h[clients[0].index])
	proof, _ := newClientProof(*context, clients[0], *tagAndCommitments, s, pushCommitments, pullChallenge)

	//Normal execution
	data, err := proof.ToBytes()
	assert.NoError(t, err,"Cannot convert valid proof to bytes")
	assert.NotNil(t, data,"Data is empty for a correct proof")
}
