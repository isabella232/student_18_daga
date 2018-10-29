package daga

import (
	"github.com/dedis/kyber"
	"github.com/stretchr/testify/require"
	"math/rand"
	"testing"
)

var suite = NewSuiteEC()

// FIXME review/see if the test are sound and were correctly written
func TestNewClient(t *testing.T) {
	//Normal execution
	i := rand.Int()
	s := suite.Scalar().Pick(suite.RandomStream())
	client, err := NewClient(suite, i, s)
	require.NoError(t, err, "Cannot initialize a new client with a given private key")
	require.Equal(t, i, client.Index(), "Cannot initialize a new client with a given private key, wrong index")
	require.True(t, client.PrivateKey().Equal(s), "Cannot initialize a new client with a given private key, wrong key")

	client, err = NewClient(suite, i, nil)
	require.NoError(t, err, "Cannot create a new client without a private key")

	//Invalid input
	client, err = NewClient(suite, -2, s)
	require.Error(t, err, "Wrong check: Invalid index")
}

func TestNewInitialTagAndCommitments(t *testing.T) {
	clients, servers, context, _ := generateTestContext(suite, rand.Intn(10)+2, rand.Intn(10)+2)

	// normal execution
	_, Y := context.Members()
	tagAndCommitments, s := newInitialTagAndCommitments(suite, Y, context.ClientsGenerators()[clients[0].Index()])
	T0, S := tagAndCommitments.T0, tagAndCommitments.SCommits
	require.NotNil(t, T0, "T0 nil")
	require.NotNil(t, S, "sCommits nil")
	require.NotNil(t, s, "s nil")
	require.False(t, T0.Equal(suite.Point().Null()), "T0 is the null point")
	require.Equal(t, len(S), len(servers)+2, "S has the wrong length: %d instead of %d", len(S), len(servers)+2)
	for i, temp := range S {
		require.False(t, temp.Equal(suite.Point().Null()), "Null point in sCommits at position %d", i)
	}
}

// test helper that sign returns a Challenge by signing the cs using the keys of the servers
func signDummyChallenge(cs kyber.Scalar, servers []Server) Challenge {
	msg, _ := cs.MarshalBinary()
	var sigs []ServerSignature
	//Make each test server sign the challenge
	for _, server := range servers {
		sig, _ := SchnorrSign(suite, server.PrivateKey(), msg)
		sigs = append(sigs, ServerSignature{Index: server.Index(), Sig: sig})
	}
	return Challenge{Cs: cs, Sigs: sigs}
}

// test helper that returns dummy "channel" to act as a dummy server/verifier
// that return challenge upon reception of the prover's commitments
func newDummyServerChannels(challenge Challenge) func([]kyber.Point) Challenge {
	sendCommitsReceiveChallenge := func([]kyber.Point) Challenge {
		return challenge
	}
	return sendCommitsReceiveChallenge
}

func TestNewClientProof(t *testing.T) {
	// setup, test context, clients, servers
	clients, servers, context, _ := generateTestContext(suite, rand.Intn(10)+2, rand.Intn(10)+2)

	// setup dummy server "channels"
	cs := suite.Scalar().Pick(suite.RandomStream())
	validChallenge := signDummyChallenge(cs, servers)
	sendCommitsReceiveChallenge := newDummyServerChannels(validChallenge)

	// normal execution, create client proof
	_, Y := context.Members()
	tagAndCommitments, s := newInitialTagAndCommitments(suite, Y, context.ClientsGenerators()[clients[0].Index()])

	proof, err := newClientProof(suite, context, clients[0], *tagAndCommitments, s, sendCommitsReceiveChallenge)
	require.NoError(t, err, "newClientProof returned an error on valid inputs")
	commits, responses, subChallenges := proof.T, proof.R, proof.C
	// FIXME not sure whether these tests are pertinent or well written... they are testing the proof framework...not my code
	require.Equal(t, len(commits), 3*len(clients))
	require.Equal(t, len(subChallenges), len(clients))
	require.Equal(t, len(responses), 2*len(clients))

	//Incorrect challenges
	var fake kyber.Scalar
	for {
		fake = suite.Scalar().Pick(suite.RandomStream())
		if !fake.Equal(cs) {
			break
		}
	}
	invalidChallenge := Challenge{Cs: fake, Sigs: validChallenge.Sigs}
	sendCommitsReceiveChallenge = newDummyServerChannels(invalidChallenge)
	proof, err = newClientProof(suite, context, clients[0], *tagAndCommitments, s, sendCommitsReceiveChallenge)
	commits, responses, subChallenges = proof.T, proof.R, proof.C
	require.Error(t, err, "newClientProof returned no error on invalid server inputs (altered challenge)")
	require.Equal(t, ClientProof{}, proof, "proof not \"zero\" on error")

	//Signature modification
	newsig := append(validChallenge.Sigs[0].Sig, []byte("A")...)
	newsig = newsig[1:]
	wrongSigs := make([]ServerSignature, len(validChallenge.Sigs))
	copy(wrongSigs, validChallenge.Sigs)
	wrongSigs[0].Sig = newsig
	invalidChallenge = Challenge{Cs: cs, Sigs: wrongSigs}
	sendCommitsReceiveChallenge = newDummyServerChannels(invalidChallenge)

	proof, err = newClientProof(suite, context, clients[0], *tagAndCommitments, s, sendCommitsReceiveChallenge)
	commits, responses, subChallenges = proof.T, proof.R, proof.C
	require.Error(t, err, "newClientProof returned no error on invalid server inputs (altered signature)")
	require.Equal(t, ClientProof{}, proof, "proof not \"zero\" on error")
}

func TestVerifyClientProof(t *testing.T) {
	// TODO maybe assemble a message using previous student code and verify with current code (but that would amount to testing the proof package)
	// setup, test context, clients, servers
	clients, servers, context, _ := generateTestContext(suite, rand.Intn(10)+2, rand.Intn(10)+2)

	// setup dummy server "channels"
	cs := suite.Scalar().Pick(suite.RandomStream())
	validChallenge := signDummyChallenge(cs, servers)
	sendCommitsReceiveChallenge := newDummyServerChannels(validChallenge)

	// create valid proof and auth. message
	_, Y := context.Members()
	tagAndCommitments, s := newInitialTagAndCommitments(suite, Y, context.ClientsGenerators()[clients[0].Index()])
	proof, _ := newClientProof(suite, context, clients[0], *tagAndCommitments, s, sendCommitsReceiveChallenge)

	clientMsg := AuthenticationMessage{
		C:                        context,
		initialTagAndCommitments: *tagAndCommitments,
		P0:                       proof,
	}

	//Normal execution
	require.NoError(t, validateAuthenticationMessage(suite, clientMsg), "Cannot validate valid client message")
	require.NoError(t, verifyAuthenticationMessage(suite, clientMsg), "Cannot verify valid client proof")

	//Modify the value of some commitments
	scratchMsg := clientMsg
	i := rand.Intn(len(clients))
	ttemp := scratchMsg.P0.T[3*i].Clone()
	scratchMsg.P0.T[3*i] = suite.Point().Null()
	require.Error(t, verifyAuthenticationMessage(suite, scratchMsg), "Incorrect check of t at index %d", 3*i)

	scratchMsg.P0.T[3*i] = ttemp.Clone()
	ttemp = scratchMsg.P0.T[3*i+1].Clone()
	scratchMsg.P0.T[3*i+1] = suite.Point().Null()
	require.Error(t, verifyAuthenticationMessage(suite, scratchMsg), "Incorrect check of t at index %d", 3*i+1)

	scratchMsg.P0.T[3*i+1] = ttemp.Clone()
	ttemp = scratchMsg.P0.T[3*i+2].Clone()
	scratchMsg.P0.T[3*i+2] = suite.Point().Null()
	require.Error(t, verifyAuthenticationMessage(suite, scratchMsg), "Incorrect check of t at index %d", 3*i+2)

	scratchMsg.P0.T[3*i+2] = ttemp.Clone()

	//tamper the challenge
	scratchMsg.P0.Cs = suite.Scalar().Zero()
	require.Error(t, verifyAuthenticationMessage(suite, scratchMsg), "Incorrect check of the challenge")
}

func TestGetFinalLinkageTag(t *testing.T) {
	// setup, test context, clients, servers, and "network channel"
	clients, servers, context, _ := generateTestContext(suite, rand.Intn(10)+2, rand.Intn(10)+1)

	// setup dummy server "channels"
	cs := suite.Scalar().Pick(suite.RandomStream())
	validChallenge := signDummyChallenge(cs, servers)
	sendCommitsReceiveChallenge := newDummyServerChannels(validChallenge)

	//Create test authMsg M0 // TODO instead of these (above and below tests too) use NewAuthMessage (=> make new Auth message easily testable by adding server channels parameters)
	_, Y := context.Members()
	tagAndCommitments, s := newInitialTagAndCommitments(suite, Y, context.ClientsGenerators()[clients[0].Index()])

	proof, _ := newClientProof(suite, context, clients[0], *tagAndCommitments, s, sendCommitsReceiveChallenge)
	clientMessage := AuthenticationMessage{
		C:                        context,
		initialTagAndCommitments: *tagAndCommitments,
		P0:                       proof,
	}

	//Create the initial server message
	servMsg := ServerMessage{Request: clientMessage, Proofs: nil, Tags: nil, Sigs: nil, Indexes: nil}

	//Run ServerProtocol on each server
	for i := range servers {
		err := ServerProtocol(suite, &servMsg, servers[i])
		require.NoError(t, err, "server %v returned an error while processing valid auth. request", i)
	}

	//Normal execution for a normal client
	Tf, err := GetFinalLinkageTag(suite, context, servMsg)
	require.NoError(t, err, "Cannot extract final linkage tag")
	require.NotNil(t, Tf, "Cannot extract final linkage tag")

	//Empty inputs
	Tf, err = GetFinalLinkageTag(suite, nil, servMsg)
	require.Error(t, err, "wrong check: Empty context")
	require.Nil(t, Tf, "wrong check: Empty context")

	Tf, err = GetFinalLinkageTag(suite, context, ServerMessage{})
	require.Error(t, err, "wrong check: Empty context")
	require.Nil(t, Tf, "wrong check: Empty context")

	//Change a signature
	servMsg.Sigs[0].Sig = append(servMsg.Sigs[0].Sig[1:], servMsg.Sigs[0].Sig[0])
	Tf, err = GetFinalLinkageTag(suite, context, servMsg)
	require.Error(t, err, "Invalid signature accepted")
	require.Nil(t, Tf, "Invalid signature accepted")

	//Revert the change
	servMsg.Sigs[0].Sig = append([]byte{0x0}, servMsg.Sigs[0].Sig...)
	servMsg.Sigs[0].Sig[0] = servMsg.Sigs[0].Sig[len(servMsg.Sigs[0].Sig)-1]
	servMsg.Sigs[0].Sig = servMsg.Sigs[0].Sig[:len(servMsg.Sigs[0].Sig)-2]

	//Misbehaving clients
	// TODO add mutliple different scenarios
	clients, servers, context, _ = generateTestContext(suite, rand.Intn(10)+2, 1)
	_, Y = context.Members()
	tagAndCommitments, s = newInitialTagAndCommitments(suite, Y, context.ClientsGenerators()[clients[0].Index()])
	// 1 server, bad tagAndCommitments, invalid proof => reject proof => cannot get (even try to get) final tag
	S := tagAndCommitments.SCommits

	S[2] = suite.Point().Null()
	validChallenge = signDummyChallenge(cs, servers)
	sendCommitsReceiveChallenge = newDummyServerChannels(validChallenge)
	proof, err = newClientProof(suite, context, clients[0], *tagAndCommitments, s, sendCommitsReceiveChallenge)
	clientMessage = AuthenticationMessage{
		C:                        context,
		initialTagAndCommitments: *tagAndCommitments,
		P0:                       proof,
	}

	//Create the initial server message
	servMsg = ServerMessage{
		Request: clientMessage,
		Proofs:  nil,
		Tags:    nil,
		Sigs:    nil,
		Indexes: nil,
	}

	//Run ServerProtocol on each server
	for i := range servers {
		err := ServerProtocol(suite, &servMsg, servers[i])
		require.Error(t, err, "server %v returned no error while processing invalid auth. request", i)
	}
	Tf, err = GetFinalLinkageTag(suite, context, servMsg)
	require.Error(t, err, "can extract final linkage tag for an invalid request, should have returned an error")
	require.Nil(t, Tf, "Tf not nil on error")
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// 1 server, bad tagAndCommitments, valid proof => flag as misbehaving => receive null final tag
	//Assemble the client message
	S = tagAndCommitments.SCommits
	S[2] = suite.Point().Null()
	tagAndCommitments.T0.Set(suite.Point().Null())
	validChallenge = signDummyChallenge(cs, servers)
	sendCommitsReceiveChallenge = newDummyServerChannels(validChallenge)
	proof, err = newClientProof(suite, context, clients[0], *tagAndCommitments, suite.Scalar().Zero(), sendCommitsReceiveChallenge)
	clientMessage = AuthenticationMessage{
		C:                        context,
		initialTagAndCommitments: *tagAndCommitments,
		P0:                       proof,
	}

	//Create the initial server message
	servMsg = ServerMessage{
		Request: clientMessage,
		Proofs:  nil,
		Tags:    nil,
		Sigs:    nil,
		Indexes: nil,
	}

	//Run ServerProtocol on each server
	for i := range servers {
		err := ServerProtocol(suite, &servMsg, servers[i])
		require.NoError(t, err, "server %v returned an error while processing auth. request of a misbehaving client", i)
	}
	Tf, err = GetFinalLinkageTag(suite, context, servMsg)
	require.NoError(t, err, "cannot extract final linkage tag for a misbehaving client")
	require.True(t, Tf.Equal(suite.Point().Null()), "Tf not Null for a misbehaving client")

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// n>1 servers, bad tagAndCommitments, valid proof => flag as misbehaving => receive null final tag
	clients, servers, context, _ = generateTestContext(suite, rand.Intn(10)+2, rand.Intn(10)+2)
	//Assemble the client message
	_, Y = context.Members()
	tagAndCommitments, s = newInitialTagAndCommitments(suite, Y, context.ClientsGenerators()[clients[0].Index()])
	S = tagAndCommitments.SCommits
	S[2] = suite.Point().Null()
	validChallenge = signDummyChallenge(cs, servers)
	sendCommitsReceiveChallenge = newDummyServerChannels(validChallenge)
	proof, err = newClientProof(suite, context, clients[0], *tagAndCommitments, s, sendCommitsReceiveChallenge)
	clientMessage = AuthenticationMessage{
		C:                        context,
		initialTagAndCommitments: *tagAndCommitments,
		P0:                       proof,
	}

	//Create the initial server message
	servMsg = ServerMessage{
		Request: clientMessage,
		Proofs:  nil,
		Tags:    nil,
		Sigs:    nil,
		Indexes: nil,
	}

	//Run ServerProtocol on each server
	for i := range servers {
		err := ServerProtocol(suite, &servMsg, servers[i])
		require.NoError(t, err, "server %v returned an error while processing auth. request of a misbehaving client", i)
	}
	Tf, err = GetFinalLinkageTag(suite, context, servMsg)
	require.NoError(t, err, "cannot extract final linkage tag for a misbehaving client")
	require.True(t, Tf.Equal(suite.Point().Null()), "Tf not Null for a misbehaving client")
}

// TODO merge or rearrange with some tests above as lots of things are redundant...or should belong to same test
// e.g see testverifyclientproof and its tampering of the p0.commitments
// + fundamentaly verify message => verify proof, so either split accordingly and test only message related things reps. proof related things in both
// or merge them together in same test and test everything
// or (but I won't lose more time on this) rewrite everything to follow best testing practises (more better named small tests for a start)
func TestValidateClientMessage(t *testing.T) {
	// setup, test context, clients, servers, and "network channel"
	clients, servers, context, _ := generateTestContext(suite, rand.Intn(10)+1, rand.Intn(10)+1)

	// setup dummy server "channels"
	cs := suite.Scalar().Pick(suite.RandomStream())
	validChallenge := signDummyChallenge(cs, servers)
	sendCommitsReceiveChallenge := newDummyServerChannels(validChallenge)

	//Create test authMsg M0
	_, Y := context.Members()
	tagAndCommitments, s := newInitialTagAndCommitments(suite, Y, context.ClientsGenerators()[clients[0].Index()])
	proof, _ := newClientProof(suite, context, clients[0], *tagAndCommitments, s, sendCommitsReceiveChallenge)
	clientMessage := AuthenticationMessage{
		C:                        context,
		initialTagAndCommitments: *tagAndCommitments,
		P0:                       proof,
	}

	//Normal execution
	// TODO already tested somewhere above...
	require.NoError(t, verifyAuthenticationMessage(suite, clientMessage), "Cannot verify valid client proof")

	//Modifying the length of various elements
	ScratchMsg := clientMessage
	ScratchMsg.P0.C = append(ScratchMsg.P0.C, suite.Scalar().Pick(suite.RandomStream()))
	require.Error(t, verifyAuthenticationMessage(suite, ScratchMsg), "Incorrect length check for c: %d instead of %d", len(ScratchMsg.P0.C), len(clients))

	ScratchMsg.P0.C = ScratchMsg.P0.C[:len(clients)-1]
	require.Error(t, verifyAuthenticationMessage(suite, ScratchMsg), "Incorrect length check for c: %d instead of %d", len(ScratchMsg.P0.C), len(clients))

	ScratchMsg = clientMessage
	ScratchMsg.P0.R = append(ScratchMsg.P0.R, suite.Scalar().Pick(suite.RandomStream()))
	require.Error(t, verifyAuthenticationMessage(suite, ScratchMsg), "Incorrect length check for r: %d instead of %d", len(ScratchMsg.P0.C), len(clients))

	ScratchMsg.P0.R = ScratchMsg.P0.R[:2*len(clients)-1]
	require.Error(t, verifyAuthenticationMessage(suite, ScratchMsg), "Incorrect length check for r: %d instead of %d", len(ScratchMsg.P0.C), len(clients))

	ScratchMsg = clientMessage
	ScratchMsg.P0.T = append(ScratchMsg.P0.T, suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil))
	require.Error(t, verifyAuthenticationMessage(suite, ScratchMsg), "Incorrect length check for t: %d instead of %d", len(ScratchMsg.P0.C), len(clients))

	ScratchMsg.P0.T = ScratchMsg.P0.T[:3*len(clients)-1]
	require.Error(t, verifyAuthenticationMessage(suite, ScratchMsg), "Incorrect length check for t: %d instead of %d", len(ScratchMsg.P0.C), len(clients))

	ScratchMsg = clientMessage
	ScratchMsg.SCommits = append(ScratchMsg.SCommits, suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil))
	require.Error(t, verifyAuthenticationMessage(suite, ScratchMsg), "Incorrect length check for S: %d instead of %d", len(ScratchMsg.SCommits), len(servers)+2)

	ScratchMsg.SCommits = ScratchMsg.SCommits[:len(servers)+1]
	require.Error(t, verifyAuthenticationMessage(suite, ScratchMsg), "Incorrect length check for S: %d instead of %d", len(ScratchMsg.SCommits), len(servers)+2)

	//Modify the value of the generator in S[1]
	ScratchMsg = clientMessage
	ScratchMsg.SCommits[1] = suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)
	require.Error(t, verifyAuthenticationMessage(suite, ScratchMsg), "Incorrect check for the generator in S[1]")

	ScratchMsg.SCommits[1] = suite.Point().Mul(suite.Scalar().One(), nil)

	//Remove T0
	ScratchMsg.T0 = nil
	require.Error(t, verifyAuthenticationMessage(suite, ScratchMsg), "Accepts a empty T0")
}

func TestToBytes_ClientMessage(t *testing.T) {
	// setup, test context, clients, servers, and "network channel"
	clients, servers, context, _ := generateTestContext(suite, rand.Intn(10)+2, rand.Intn(10)+1)

	// setup dummy server "channels"
	cs := suite.Scalar().Pick(suite.RandomStream())
	validChallenge := signDummyChallenge(cs, servers)
	sendCommitsReceiveChallenge := newDummyServerChannels(validChallenge)

	//Create test authMsg M0  // TODO instead of these (above and below tests too) use NewAuthMessage (=> make new Auth message easily testable by adding server channels parameters)
	_, Y := context.Members()
	tagAndCommitments, s := newInitialTagAndCommitments(suite, Y, context.ClientsGenerators()[clients[0].Index()])
	proof, _ := newClientProof(suite, context, clients[0], *tagAndCommitments, s, sendCommitsReceiveChallenge)
	clientMessage := AuthenticationMessage{
		C:                        context,
		initialTagAndCommitments: *tagAndCommitments,
		P0:                       proof,
	}

	//Normal execution
	data, err := clientMessage.ToBytes()
	require.NoError(t, err, "Cannot convert valid Client Message to bytes")
	require.NotNil(t, data, "Data is empty for a correct Client Message")
}

func TestToBytes_ClientProof(t *testing.T) {
	// setup, test context, clients, servers, and "network channel"
	clients, servers, context, _ := generateTestContext(suite, rand.Intn(10)+2, rand.Intn(10)+1)

	// setup dummy server "channels"
	cs := suite.Scalar().Pick(suite.RandomStream())
	validChallenge := signDummyChallenge(cs, servers)
	sendCommitsReceiveChallenge := newDummyServerChannels(validChallenge)

	//Create test client proof
	_, Y := context.Members()
	tagAndCommitments, s := newInitialTagAndCommitments(suite, Y, context.ClientsGenerators()[clients[0].Index()])
	proof, _ := newClientProof(suite, context, clients[0], *tagAndCommitments, s, sendCommitsReceiveChallenge)

	//Normal execution
	data, err := proof.ToBytes()
	require.NoError(t, err, "Cannot convert valid proof to bytes")
	require.NotNil(t, data, "Data is empty for a correct proof")
}
