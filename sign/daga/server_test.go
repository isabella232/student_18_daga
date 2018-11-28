package daga

import (
	"crypto/sha512"
	"github.com/dedis/kyber"
	"github.com/stretchr/testify/require"
	"io"
	"math/rand"
	"testing"
)

func TestNewServer(t *testing.T) {
	//Normal execution
	i := rand.Int()
	s := suite.Scalar().Pick(suite.RandomStream())
	server, err := NewServer(suite, i, s)
	require.NoError(t, err, "Cannot initialize a new server with a given private key")
	require.Equal(t, server.Index(), i, "Cannot initialize a new server with a given private key, wrong index")
	require.True(t, server.PrivateKey().Equal(s), "Cannot initialize a new server with a given private key, wrong key")

	server, err = NewServer(suite, i, nil)
	require.NoError(t, err, "Cannot create a new server without a private key")
	require.NotNil(t, server.PrivateKey(), "Cannot create a new server without a private key")

	//Invalid input
	server, err = NewServer(suite, -2, s)
	require.Error(t, err, "Wrong check: Invalid index")
}

func TestGetPublicKey_Server(t *testing.T) {
	server, _ := NewServer(suite, 0, suite.Scalar().Pick(suite.RandomStream()))
	P := server.PublicKey()
	require.NotNil(t, P, "Cannot get public key")
}

func TestGenerateCommitment(t *testing.T) {
	_, servers, _, _ := GenerateTestContext(suite, rand.Intn(10)+2, rand.Intn(10)+1)

	//Normal execution
	commit, opening, err := NewChallengeCommitment(suite, servers[0])
	require.NoError(t, err, "Cannot generate a commitment")
	require.True(t, commit.Commit.Equal(suite.Point().Mul(opening, nil)), "Cannot open the commitment")

	msg, err := commit.Commit.MarshalBinary()
	require.NoError(t, err, "failed to marshall commitment")

	err = SchnorrVerify(suite, servers[0].PublicKey(), msg, commit.Sig)
	require.NoError(t, err, "wrong commitment signature, failed to verify")
}

func TestVerifyCommitmentSignature(t *testing.T) {
	_, servers, context, _ := GenerateTestContext(suite, rand.Intn(10)+1, rand.Intn(10)+1)

	//Generate commitments
	var commits []ChallengeCommitment
	for _, server := range servers {
		commit, _, _ := NewChallengeCommitment(suite, server)
		commits = append(commits, *commit)
	}

	//Normal execution
	err := VerifyChallengeCommitmentsSignatures(suite, context, commits)
	require.NoError(t, err, "Cannot verify the signatures for a legit commit array")

	//Change a random index
	i := rand.Intn(len(servers))
	commits[i].Index = i + 1
	err = VerifyChallengeCommitmentsSignatures(suite, context, commits)
	require.Error(t, err, "Cannot verify matching indexes for %d", i)

	commits[i].Index = i + 1

	//Change a signature
	//Code shown as not covered, but it does detect the modification and returns an error <- QUESTION ??
	sig := commits[i].Sig
	sig = append(sig, []byte("A")...)
	sig = sig[1:]
	commits[i].Sig = sig
	err = VerifyChallengeCommitmentsSignatures(suite, context, commits)
	require.Error(t, err, "Cannot verify signature for %d", i)
}

func TestCheckOpenings(t *testing.T) {
	_, servers, context, _ := GenerateTestContext(suite, rand.Intn(10)+1, rand.Intn(10)+1)

	//Generate commitments
	var commits []ChallengeCommitment
	var openings []kyber.Scalar
	for i := 0; i < len(servers); i++ {
		commit, open, _ := NewChallengeCommitment(suite, servers[i])
		commits = append(commits, *commit)
		openings = append(openings, open)
	}

	//Normal execution
	cs, err := checkOpenings(suite, context, commits, openings)
	require.NoError(t, err, "Cannot check the openings")

	challenge := suite.Scalar().Zero()
	for _, temp := range openings {
		challenge = suite.Scalar().Add(challenge, temp)
	}
	require.True(t, cs.Equal(challenge), "Wrong computation of challenge cs: %s instead of %s", cs, challenge)

	//Empty inputs
	cs, err = checkOpenings(suite, nil, commits, openings)
	require.Error(t, err, "Wrong check: Empty *context")

	require.Nil(t, cs, "cs not nil on empty *context")

	cs, err = checkOpenings(suite, context, nil, openings)
	require.Error(t, err, "Wrong check: Empty commits")
	require.Nil(t, cs, "cs not nil on empty commits")

	cs, err = checkOpenings(suite, context, commits, nil)
	require.Error(t, err, "Wrong check: Empty openings")
	require.Nil(t, cs, "cs not nil on empty openings")

	//Change the length of the openings
	CutOpenings := openings[:len(openings)-1]
	cs, err = checkOpenings(suite, context, commits, CutOpenings)
	require.Error(t, err, "Invalid length check on openings")
	require.Nil(t, cs, "cs not nil on opening length error")

	//Change the length of the commits
	CutCommits := commits[:len(commits)-1]
	cs, err = checkOpenings(suite, context, CutCommits, openings)
	require.Error(t, err, "Invalid length check on comits")
	require.Nil(t, cs, "cs not nil on commit length error")

	//Change a random opening
	i := rand.Intn(len(servers))
	openings[i] = suite.Scalar().Zero()
	cs, err = checkOpenings(suite, context, commits, openings)
	require.Error(t, err, "Invalid opening check")
	require.Nil(t, cs, "cs not nil on opening error")
}

func TestInitializeChallenge(t *testing.T) {
	_, servers, context, _ := GenerateTestContext(suite, rand.Intn(10)+1, rand.Intn(10)+1)

	//Generate commitments
	var commits []ChallengeCommitment
	var openings []kyber.Scalar
	for i := 0; i < len(servers); i++ {
		commit, open, _ := NewChallengeCommitment(suite, servers[i])
		commits = append(commits, *commit)
		openings = append(openings, open)
	}

	//Normal execution
	challenge, err := InitializeChallenge(suite, context, commits, openings)
	require.NoError(t, err, "Cannot initialize challenge")
	require.NotNil(t, challenge, "Cannot initialize challenge")

	//Empty inputs
	challenge, err = InitializeChallenge(suite, nil, commits, openings)
	require.Error(t, err, "Wrong check: Empty cs")
	require.Nil(t, challenge, "Wrong check: Empty cs")

	challenge, err = InitializeChallenge(suite, context, nil, openings)
	require.Error(t, err, "Wrong check: Empty commits")
	require.Nil(t, challenge, "Wrong check: Empty commits")

	challenge, err = InitializeChallenge(suite, context, commits, nil)
	require.Error(t, err, "Wrong check: Empty openings")
	require.Nil(t, challenge, "Wrong check: Empty openings")

	//Mismatch length between commits and openings
	challenge, err = InitializeChallenge(suite, context, commits, openings[:len(openings)-2])
	require.Error(t, err, "Wrong check: Mismatched length between commits and openings")
	require.Nil(t, challenge, "Wrong check: Mismatched length between commits and openings")

	//Change an opening
	openings[0] = suite.Scalar().Zero()
	challenge, err = InitializeChallenge(suite, context, commits, openings[:len(openings)-2])
	require.Error(t, err, "Invalid opening check")
	require.Nil(t, challenge, "Invalid opening check")
}

func TestCheckUpdateChallenge(t *testing.T) {
	//The following tests need at least 2 servers
	clients, servers, context, _ := GenerateTestContext(suite, rand.Intn(10)+1, rand.Intn(10)+2)

	//Generate commitments
	var commits []ChallengeCommitment
	var openings []kyber.Scalar
	for i := 0; i < len(servers); i++ {
		commit, open, _ := NewChallengeCommitment(suite, servers[i])
		commits = append(commits, *commit)
		openings = append(openings, open)
	}

	challenge, _ := InitializeChallenge(suite, context, commits, openings)
	cs := challenge.Cs

	// TODO share randompointhelper with the daga_login testing package
	var dummyPKClientCommitments []kyber.Point
	for _, _ = range clients {
		dummyPKClientCommitments = append(dummyPKClientCommitments, suite.Point().Pick(suite.RandomStream()))
	}

	//Normal execution
	err := CheckUpdateChallenge(suite, context, challenge, dummyPKClientCommitments, servers[0])
	require.NoError(t, err, "Cannot update the challenge")
	require.Equal(t, len(challenge.Sigs), 1, "Did not correctly add the signature")

	//Duplicate signature
	challenge.Sigs = append(challenge.Sigs, challenge.Sigs[0])
	err = CheckUpdateChallenge(suite, context, challenge, dummyPKClientCommitments, servers[0])
	require.Error(t, err, "Does not check for duplicates signatures")

	challenge.Sigs = []ServerSignature{challenge.Sigs[0]}

	//Altered signature
	fake := append([]byte("A"), challenge.Sigs[0].Sig...)
	challenge.Sigs[0].Sig = fake[:len(challenge.Sigs[0].Sig)]
	err = CheckUpdateChallenge(suite, context, challenge, dummyPKClientCommitments, servers[0])
	require.Error(t, err, "Wrond check of signature")

	//Restore correct signature for the next tests
	challenge.Sigs = nil
	CheckUpdateChallenge(suite, context, challenge, dummyPKClientCommitments, servers[0])

	//Modify the challenge
	challenge.Cs = suite.Scalar().Zero()
	err = CheckUpdateChallenge(suite, context, challenge, dummyPKClientCommitments, servers[0])
	require.Error(t, err, "Does not check the challenge")

	challenge.Cs = cs

	//Only appends if the challenge has not already done a round-robin
	for _, server := range servers[1:] {
		err = CheckUpdateChallenge(suite, context, challenge, dummyPKClientCommitments, server)
		require.NoError(t, err, "Error during the round-robin at server %d", server.Index())
	}
	err = CheckUpdateChallenge(suite, context, challenge, dummyPKClientCommitments, servers[0])
	require.NoError(t, err, "Error when closing the loop of the round-robin")
	require.Equal(t, len(challenge.Sigs), len(servers), "Invalid number of signatures: %d instead of %d", len(challenge.Sigs), len(servers))

	//Change a commitment
	challenge.Commits[0].Commit = suite.Point().Mul(suite.Scalar().One(), nil)
	err = CheckUpdateChallenge(suite, context, challenge, dummyPKClientCommitments, servers[0])
	require.Error(t, err, "Invalid commitment signature check")

	challenge.Commits[0].Commit = suite.Point().Mul(challenge.Openings[0], nil)

	//Change an opening
	challenge.Openings[0] = suite.Scalar().Zero()
	err = CheckUpdateChallenge(suite, context, challenge, dummyPKClientCommitments, servers[0])
	require.Error(t, err, "Invalid opening check")
}

func TestFinalizeChallenge(t *testing.T) {
	//The following tests need at least 2 servers
	clients, servers, context, _ := GenerateTestContext(suite, rand.Intn(10)+1, rand.Intn(10)+2)

	//Generate commitments
	var commits []ChallengeCommitment
	var openings []kyber.Scalar
	for i := 0; i < len(servers); i++ {
		commit, open, _ := NewChallengeCommitment(suite, servers[i])
		commits = append(commits, *commit)
		openings = append(openings, open)
	}

	// TODO share randompointhelper with the daga_login testing package
	var dummyPKClientCommitments []kyber.Point
	for _, _ = range clients {
		dummyPKClientCommitments = append(dummyPKClientCommitments, suite.Point().Pick(suite.RandomStream()))
	}

	challenge, _ := InitializeChallenge(suite, context, commits, openings)

	//Makes every server update the challenge
	var err error
	for _, server := range servers[1:] {
		err = CheckUpdateChallenge(suite, context, challenge, dummyPKClientCommitments, server)
		require.NoError(t, err, "Error during the round-robin at server %d", server.Index())
	}

	//Normal execution
	//Let's say that server 0 is the leader and received the message back
	CheckUpdateChallenge(suite, context, challenge, dummyPKClientCommitments, servers[0])
	clientChallenge, err := FinalizeChallenge(context, challenge)
	require.NoError(t, err, "Error during finalization of the challenge")

	//Check cs value
	require.True(t, clientChallenge.Cs.Equal(challenge.Cs), "cs values does not match")

	//Check number of signatures
	require.Equal(t, len(clientChallenge.Sigs), len(challenge.Sigs), "Signature count does not match: got %d expected %d", len(clientChallenge.Sigs), len(challenge.Sigs))

	//Empty inputs
	clientChallenge, err = FinalizeChallenge(nil, challenge)
	require.Error(t, err, "Wrong check: Empty *context")
	require.Zero(t, clientChallenge, "Wrong check: Empty *context")

	clientChallenge, err = FinalizeChallenge(context, nil)
	require.Error(t, err, "Wrong check: Empty challenge")
	require.Zero(t, clientChallenge, "Wrong check: Empty challenge")

	//Add a signature
	challenge.Sigs = append(challenge.Sigs, challenge.Sigs[0])
	clientChallenge, err = FinalizeChallenge(context, challenge)
	require.Error(t, err, "Wrong check: Higher signature count")
	require.Zero(t, clientChallenge, "Wrong check: Higher signature count")

	//Remove a signature
	challenge.Sigs = challenge.Sigs[:len(challenge.Sigs)-2]
	clientChallenge, err = FinalizeChallenge(context, challenge)
	require.Error(t, err, "Wrong check: Lower signature count")
	require.Zero(t, clientChallenge, "Wrong check: Lower signature count")
}

// TODO port to new implementation rhaaa
func TestInitializeServerMessage(t *testing.T) {
	// TODO test for one server as we saw that it previously triggered an hidden bug
	clients, servers, context, _ := GenerateTestContext(suite, 2, 2)
	for _, server := range servers {
		if server.RoundSecret() == nil {
			t.Errorf("Error in r for server %d", server.Index())
		}
	}
	members := context.Members()
	tagAndCommitments, s := newInitialTagAndCommitments(suite, members.Y, context.ClientsGenerators()[clients[0].Index()])

	// setup test server "channels" with valid dummy challenge
	sendCommitsReceiveChallenge := newDummyServerChannels(suite.Scalar().Pick(suite.RandomStream()), servers)

	//Assemble the client message
	proof, err := newClientProof(suite, context, clients[0], *tagAndCommitments, s, sendCommitsReceiveChallenge)
	require.NoError(t, err, "failed to generate client proof, this is not expected")
	clientMessage := AuthenticationMessage{
		C:                        context,
		initialTagAndCommitments: *tagAndCommitments,
		P0:                       proof,
	}

	//Normal execution
	servMsg, err := InitializeServerMessage(&clientMessage)
	if err != nil || servMsg == nil || len(servMsg.Indexes) != 0 || len(servMsg.Proofs) != 0 || len(servMsg.Tags) != 0 || len(servMsg.Sigs) != 0 {
		t.Error("Cannot initialize server message")
	}

	//Empty request
	servMsg, err = InitializeServerMessage(nil)
	require.Error(t, err, "Wrong check: Empty request")
	require.Nil(t, servMsg, "Wrong check: Empty request")
}

func TestServerProtocol(t *testing.T) {
	clients, servers, context, _ := GenerateTestContext(suite, 2, 2)
	for _, server := range servers {
		require.NotNil(t, server.RoundSecret(), "Error in r for server %d", server.Index())
	}
	members := context.Members()
	tagAndCommitments, s := newInitialTagAndCommitments(suite, members.Y, context.ClientsGenerators()[clients[0].Index()])

	// setup test server "channels" with valid dummy challenge
	sendCommitsReceiveChallenge := newDummyServerChannels(suite.Scalar().Pick(suite.RandomStream()), servers)

	//Assemble the client message
	proof, err := newClientProof(suite, context, clients[0], *tagAndCommitments, s, sendCommitsReceiveChallenge)
	require.NoError(t, err, "failed to generate client proof, this is not expected")
	clientMessage := AuthenticationMessage{
		C:                        context,
		initialTagAndCommitments: *tagAndCommitments,
		P0:                       proof,
	}

	//Original hash for later test
	hasher := sha512.New()
	var writer io.Writer = hasher
	data, _ := clientMessage.ToBytes()
	writer.Write(data)
	hash := hasher.Sum(nil)

	//Create the initial server message
	servMsg := ServerMessage{Request: clientMessage, Proofs: nil, Tags: nil, Sigs: nil, Indexes: nil}

	//Normal execution for correct client
	err = ServerProtocol(suite, &servMsg, servers[0])
	require.NoError(t, err, "Error in Server Protocol\n%s", err)

	err = ServerProtocol(suite, &servMsg, servers[1])
	require.NoError(t, err, "Error in Server Protocol for server 1\n%s", err)

	//Check that elements were added to the message
	require.Equal(t, 2, len(servMsg.Indexes), "Incorrect number of elements added to the message: %d instead of 2", len(servMsg.Indexes))

	//Empty request
	emptyMsg := ServerMessage{Request: AuthenticationMessage{}, Proofs: servMsg.Proofs, Tags: servMsg.Tags, Sigs: servMsg.Sigs, Indexes: servMsg.Indexes}
	err = ServerProtocol(suite, &emptyMsg, servers[0])
	require.Error(t, err, "Wrong check: Empty request")

	//Different lengths
	wrongMsg := ServerMessage{Request: clientMessage, Proofs: servMsg.Proofs, Tags: servMsg.Tags, Sigs: servMsg.Sigs, Indexes: servMsg.Indexes}
	wrongMsg.Indexes = wrongMsg.Indexes[:len(wrongMsg.Indexes)-2]
	err = ServerProtocol(suite, &wrongMsg, servers[0])
	require.Error(t, err, "Wrong check: different field length of indexes")

	wrongMsg = ServerMessage{Request: clientMessage, Proofs: servMsg.Proofs, Tags: servMsg.Tags, Sigs: servMsg.Sigs, Indexes: servMsg.Indexes}
	wrongMsg.Tags = wrongMsg.Tags[:len(wrongMsg.Tags)-2]
	err = ServerProtocol(suite, &wrongMsg, servers[0])
	require.Error(t, err, "Wrong check: different field length of tags")

	wrongMsg = ServerMessage{Request: clientMessage, Proofs: servMsg.Proofs, Tags: servMsg.Tags, Sigs: servMsg.Sigs, Indexes: servMsg.Indexes}
	wrongMsg.Proofs = wrongMsg.Proofs[:len(wrongMsg.Proofs)-2]
	err = ServerProtocol(suite, &wrongMsg, servers[0])
	require.Error(t, err, "Wrong check: different field length of proofs")

	wrongMsg = ServerMessage{Request: clientMessage, Proofs: servMsg.Proofs, Tags: servMsg.Tags, Sigs: servMsg.Sigs, Indexes: servMsg.Indexes}
	wrongMsg.Sigs = wrongMsg.Sigs[:len(wrongMsg.Sigs)-2]
	err = ServerProtocol(suite, &wrongMsg, servers[0])
	require.Error(t, err, "Wrong check: different field length of signatures")

	//Modify the client proof
	wrongClient := ServerMessage{Request: clientMessage, Proofs: servMsg.Proofs, Tags: servMsg.Tags, Sigs: servMsg.Sigs, Indexes: servMsg.Indexes}
	wrongClient.Request.P0 = ClientProof{}
	err = ServerProtocol(suite, &wrongMsg, servers[0])
	require.Error(t, err, "Wrong check: invalid client proof")

	//Too many calls
	err = ServerProtocol(suite, &servMsg, servers[0])
	require.Error(t, err, "Wrong check: Too many calls")

	//The client request is left untouched
	hasher2 := sha512.New()
	var writer2 io.Writer = hasher2
	data2, _ := servMsg.Request.ToBytes()
	writer2.Write(data2)
	hash2 := hasher2.Sum(nil)

	for i := range hash {
		require.Equal(t, hash[i], hash2[i], "Client's request modified")
	}

	//Normal execution for misbehaving client
	misbehavingMsg := ServerMessage{Request: clientMessage, Proofs: nil, Tags: nil, Sigs: nil, Indexes: nil}
	misbehavingMsg.Request.SCommits[2] = suite.Point().Null() //change the commitment for server 0
	err = ServerProtocol(suite, &misbehavingMsg, servers[0])
	require.NoError(t, err, "Error in Server Protocol for misbehaving client\n%s", err)

	err = ServerProtocol(suite, &misbehavingMsg, servers[1])
	require.NoError(t, err, "Error in Server Protocol for misbehaving client and server 1\n%s", err)
}

func TestGenerateServerProof(t *testing.T) {
	clients, servers, context, _ := GenerateTestContext(suite, 2, 2)
	members := context.Members()
	tagAndCommitments, s := newInitialTagAndCommitments(suite, members.Y, context.ClientsGenerators()[clients[0].Index()])
	T0, _ := tagAndCommitments.T0, tagAndCommitments.SCommits

	// setup test server "channels" with valid dummy challenge
	sendCommitsReceiveChallenge := newDummyServerChannels(suite.Scalar().Pick(suite.RandomStream()), servers)

	//Assemble the client message
	proof, err := newClientProof(suite, context, clients[0], *tagAndCommitments, s, sendCommitsReceiveChallenge)
	require.NoError(t, err, "failed to generate client proof, this is not expected")
	clientMessage := AuthenticationMessage{
		C:                        context,
		initialTagAndCommitments: *tagAndCommitments,
		P0:                       proof,
	}

	//Create the initial server message
	servMsg := ServerMessage{Request: clientMessage, Proofs: nil, Tags: nil, Sigs: nil, Indexes: nil}

	//Prepare the proof
	hasher := sha512.New()
	var writer io.Writer = hasher // ...
	suite.Point().Mul(servers[0].PrivateKey(), servMsg.Request.SCommits[0]).MarshalTo(writer)
	hash := hasher.Sum(nil)
	hasher = suite.Hash()
	hasher.Write(hash)
	//rand := suite.Cipher(hash)
	secret := suite.Scalar().SetBytes(hasher.Sum(nil))

	inv := suite.Scalar().Inv(secret)
	exp := suite.Scalar().Mul(servers[0].RoundSecret(), inv)
	T := suite.Point().Mul(exp, T0)

	//Normal execution
	serverProof, err := generateServerProof(suite, context, secret, T, &servMsg, servers[0])
	require.NoError(t, err, "Cannot generate normal server proof")
	require.NotNil(t, serverProof, "Cannot generate normal server proof")

	//Correct format
	if serverProof.T1 == nil || serverProof.T2 == nil || serverProof.T3 == nil {
		t.Error("Incorrect tags in proof")
	}
	require.NotNil(t, serverProof.C, "Incorrect challenge")

	require.NotNil(t, serverProof.R1, "Incorrect responses")
	require.NotNil(t, serverProof.R2, "Incorrect responses")

	//Invalid inputs
	serverProof, err = generateServerProof(suite, nil, secret, T, &servMsg, servers[0])
	require.Error(t, err, "Wrong check: Invalid *context")
	require.Nil(t, serverProof, "Wrong check: Invalid *context")

	serverProof, err = generateServerProof(suite, context, nil, T, &servMsg, servers[0])
	require.Error(t, err, "Wrong check: Invalid secret")
	require.Nil(t, serverProof, "Wrong check: Invalid secret")

	serverProof, err = generateServerProof(suite, context, secret, nil, &servMsg, servers[0])
	require.Error(t, err, "Wrong check: Invalid tag")
	require.Nil(t, serverProof, "Wrong check: Invalid tag")

	serverProof, err = generateServerProof(suite, context, secret, T, nil, servers[0])
	require.Error(t, err, "Wrong check: Invalid Server Message")
	require.Nil(t, serverProof, "Wrong check: Invalid Server Message")
}

func TestVerifyServerProof(t *testing.T) {
	clients, servers, context, _ := GenerateTestContext(suite, 2, rand.Intn(10)+2)
	members := context.Members()
	tagAndCommitments, s := newInitialTagAndCommitments(suite, members.Y, context.ClientsGenerators()[clients[0].Index()])

	// setup test server "channels" with valid dummy challenge
	sendCommitsReceiveChallenge := newDummyServerChannels(suite.Scalar().Pick(suite.RandomStream()), servers)

	//Assemble the client message
	clientProof, err := newClientProof(suite, context, clients[0], *tagAndCommitments, s, sendCommitsReceiveChallenge)
	require.NoError(t, err, "failed to generate client proof, this is not expected")
	clientMessage := AuthenticationMessage{
		C:                        context,
		initialTagAndCommitments: *tagAndCommitments,
		P0:                       clientProof,
	}

	servMsg := ServerMessage{Request: clientMessage, Proofs: nil, Tags: nil, Sigs: nil, Indexes: nil}

	err = ServerProtocol(suite, &servMsg, servers[0])
	require.NoError(t, err)
	// TODO, I replaced the commented code below by the call above (which is perfectly sound) but this triggers new questions,
	// TODO => serverprotocol => verifyserverproof, reorganize tests or rewrite everything to follow testing guidelines or make sure everything is in the right place
	////Prepare the proof
	//hasher := suite.Hash()
	//suite.Point().Mul(servers[0].key.Private, servMsg.request.sCommits[0]).MarshalTo(hasher)
	////rand := suite.Cipher(hash)
	//secret := suite.Scalar().SetBytes(hasher.Sum(nil))
	//
	//inv := suite.Scalar().Inv(secret)
	//exp := suite.Scalar().Mul(servers[0].r, inv)
	//T := suite.Point().Mul(exp, tagAndCommitments.t0)
	//
	////Generate the proof
	//proof, _ := servers[0].generateServerProof(suite, context, secret, T, &servMsg)
	//servMsg.proofs = append(servMsg.proofs, *proof)
	//servMsg.tags = append(servMsg.tags, T)
	//servMsg.indexes = append(servMsg.indexes, servers[0].Index())
	//
	////Signs our message
	//data, _ := servMsg.request.ToBytes()
	//temp, _ := T.MarshalBinary()
	//data = append(data, temp...)
	//temp, _ = proof.ToBytes()
	//data = append(data, temp...)
	//data = append(data, []byte(strconv.Itoa(servers[0].Index()))...)
	//sign, _ := ECDSASign(servers[0].key.Private, data)
	//signature := ServerSignature{sig: sign, index: servers[0].Index()}
	//servMsg.sigs = append(servMsg.sigs, signature)
	//
	////Verify first server proof
	//check := verifyServerProof(suite, context, 0, &servMsg)
	//if !check {
	//	t.Error("Cannot verify first valid normal server proof")
	//}

	err = ServerProtocol(suite, &servMsg, servers[1])
	require.NoError(t, err)

	//Verify any server proof
	check := verifyServerProof(suite, context, 1, &servMsg)
	require.True(t, check, "Cannot verify valid normal server proof")

	saveProof := ServerProof{C: servMsg.Proofs[1].C,
		T1: servMsg.Proofs[1].T1,
		T2: servMsg.Proofs[1].T2,
		T3: servMsg.Proofs[1].T3,
		R1: servMsg.Proofs[1].R1,
		R2: servMsg.Proofs[1].R2,
	}

	//Check inputs
	servMsg.Proofs[1].C = nil
	check = verifyServerProof(suite, context, 1, &servMsg)
	require.False(t, check, "Error in challenge verification")
	servMsg.Proofs[1].C = saveProof.C

	servMsg.Proofs[1].T1 = nil
	check = verifyServerProof(suite, context, 1, &servMsg)
	require.False(t, check, "Error in t1 verification")
	servMsg.Proofs[1].T1 = saveProof.T1

	servMsg.Proofs[1].T2 = nil
	check = verifyServerProof(suite, context, 1, &servMsg)
	require.False(t, check, "Error in t2 verification")
	servMsg.Proofs[1].T2 = saveProof.T2

	servMsg.Proofs[1].T3 = nil
	check = verifyServerProof(suite, context, 1, &servMsg)
	require.False(t, check, "Error in t3 verification")
	servMsg.Proofs[1].T3 = saveProof.T3

	servMsg.Proofs[1].R1 = nil
	check = verifyServerProof(suite, context, 1, &servMsg)
	require.False(t, check, "Error in r1 verification")
	servMsg.Proofs[1].R1 = saveProof.R1

	servMsg.Proofs[1].R2 = nil
	check = verifyServerProof(suite, context, 1, &servMsg)
	require.False(t, check, "Error in r2 verification")
	servMsg.Proofs[1].R2 = saveProof.R2

	//Invalid *context
	check = verifyServerProof(suite, nil, 1, &servMsg)
	require.False(t, check, "Wrong check: Invalid *context")

	//nil message
	check = verifyServerProof(suite, context, 1, nil)
	require.False(t, check, "Wrong check: Invalid message")

	//Invalid value of i
	check = verifyServerProof(suite, context, 2, &servMsg)
	require.False(t, check, "Wrong check: Invalid i value")

	check = verifyServerProof(suite, context, -2, &servMsg)
	require.False(t, check, "Wrong check: Negative i value")
}

func TestGenerateMisbehavingProof(t *testing.T) {
	clients, servers, context, _ := GenerateTestContext(suite, 2, 2)
	members := context.Members()
	tagAndCommitments, s := newInitialTagAndCommitments(suite, members.Y, context.ClientsGenerators()[clients[0].Index()])

	// setup test server "channels" with valid dummy challenge
	sendCommitsReceiveChallenge := newDummyServerChannels(suite.Scalar().Pick(suite.RandomStream()), servers)

	//Assemble the client message
	proof, err := newClientProof(suite, context, clients[0], *tagAndCommitments, s, sendCommitsReceiveChallenge)
	require.NoError(t, err, "failed to generate client proof, this is not expected")
	clientMessage := AuthenticationMessage{
		C:                        context,
		initialTagAndCommitments: *tagAndCommitments,
		P0:                       proof,
	}

	serverProof, err := generateMisbehavingProof(suite, clientMessage.SCommits[0], servers[0])
	if err != nil || serverProof == nil {
		t.Error("Cannot generate misbehaving proof")
	}

	//Correct format
	require.NotNil(t, serverProof.T1, "t1 nil for misbehaving proof")
	require.NotNil(t, serverProof.T2, "t2 nil for misbehaving proof")
	require.NotNil(t, serverProof.T3, "t3 nil for misbehaving proof")
	require.NotNil(t, serverProof.C, "c nil for misbehaving proof")
	require.NotNil(t, serverProof.R1, "r1 nil for misbehaving proof")
	require.Nil(t, serverProof.R2, "r2 not nil for misbehaving proof")

	//Invalid inputs
	serverProof, err = generateMisbehavingProof(suite, nil, servers[0])
	require.Error(t, err, "Wrong check: Invalid Z")
	require.Nil(t, serverProof, "Wrong check: Invalid Z")
}

func TestVerifyMisbehavingProof(t *testing.T) {
	clients, servers, context, _ := GenerateTestContext(suite, 2, 2)
	members := context.Members()
	tagAndCommitments, s := newInitialTagAndCommitments(suite, members.Y, context.ClientsGenerators()[clients[0].Index()])

	// setup test server "channels" with valid dummy challenge
	sendCommitsReceiveChallenge := newDummyServerChannels(suite.Scalar().Pick(suite.RandomStream()), servers)

	//Assemble the client message
	clientProof, err := newClientProof(suite, context, clients[0], *tagAndCommitments, s, sendCommitsReceiveChallenge)
	require.NoError(t, err, "failed to generate client proof, this is not expected")
	clientMessage := AuthenticationMessage{
		C:                        context,
		initialTagAndCommitments: *tagAndCommitments,
		P0:                       clientProof,
	}

	proof, _ := generateMisbehavingProof(suite, clientMessage.SCommits[0], servers[0])

	check := verifyMisbehavingProof(suite, servers[0].PublicKey(), proof, clientMessage.SCommits[0])
	require.True(t, check, "Cannot verify valid misbehaving proof")

	//Invalid inputs
	check = verifyMisbehavingProof(suite, nil, proof, clientMessage.SCommits[0])
	require.False(t, check, "Wrong check: Invalid public key")

	check = verifyMisbehavingProof(suite, servers[1].PublicKey(), proof, clientMessage.SCommits[0])
	require.False(t, check, "Wrong check: Invalid index")

	check = verifyMisbehavingProof(suite, servers[0].PublicKey(), nil, clientMessage.SCommits[0])
	require.False(t, check, "Wrong check: Missing proof")

	check = verifyMisbehavingProof(suite, servers[0].PublicKey(), proof, nil)
	require.False(t, check, "Wrong check: Invalid Z")

	//Modify proof values
	proof, _ = generateMisbehavingProof(suite, clientMessage.SCommits[0], servers[0])
	saveProof := ServerProof{
		C:  proof.C,
		T1: proof.T1,
		T2: proof.T2,
		T3: proof.T3,
		R1: proof.R1,
		R2: proof.R2,
	}

	//Check inputs
	proof.C = nil
	check = verifyMisbehavingProof(suite, servers[0].PublicKey(), proof, clientMessage.SCommits[0])
	require.False(t, check, "Error in challenge verification")
	proof.C = saveProof.C

	proof.T1 = nil
	check = verifyMisbehavingProof(suite, servers[0].PublicKey(), proof, clientMessage.SCommits[0])
	require.False(t, check, "Error in t1 verification")
	proof.T1 = saveProof.T1

	proof.T2 = nil
	check = verifyMisbehavingProof(suite, servers[0].PublicKey(), proof, clientMessage.SCommits[0])
	require.False(t, check, "Error in t2 verification")
	proof.T2 = saveProof.T2

	proof.T3 = nil
	check = verifyMisbehavingProof(suite, servers[0].PublicKey(), proof, clientMessage.SCommits[0])
	require.False(t, check, "Error in t3 verification")
	proof.T3 = saveProof.T3

	proof.R1 = nil
	check = verifyMisbehavingProof(suite, servers[0].PublicKey(), proof, clientMessage.SCommits[0])
	require.False(t, check, "Error in r1 verification")
	proof.R1 = saveProof.R1

	proof.R2 = suite.Scalar().One()
	check = verifyMisbehavingProof(suite, servers[0].PublicKey(), proof, clientMessage.SCommits[0])
	require.False(t, check, "Error in r2 verification")
	proof.R2 = saveProof.R2
	// TODO: Complete the tests
}

func TestGenerateNewRoundSecret(t *testing.T) {
	_, servers, _, _ := GenerateTestContext(suite, 1, 1)
	R := GenerateNewRoundSecret(suite, servers[0])
	//servers[0] = server
	require.NotNil(t, R, "Cannot generate new round secret")
	require.False(t, R.Equal(suite.Point().Mul(suite.Scalar().One(), nil)), "R is the generator")
	require.NotNil(t, servers[0].RoundSecret(), "r was not saved to the server")
	require.True(t, R.Equal(suite.Point().Mul(servers[0].RoundSecret(), nil)), "Mismatch between r and R")
}

func TestToBytes_ServerProof(t *testing.T) {
	clients, servers, context, _ := GenerateTestContext(suite, 2, 2)
	members := context.Members()
	tagAndCommitments, s := newInitialTagAndCommitments(suite, members.Y, context.ClientsGenerators()[clients[0].Index()])
	_, S := tagAndCommitments.T0, tagAndCommitments.SCommits

	// setup test server "channels" with valid dummy challenge
	sendCommitsReceiveChallenge := newDummyServerChannels(suite.Scalar().Pick(suite.RandomStream()), servers)

	//Assemble the client message
	clientProof, err := newClientProof(suite, context, clients[0], *tagAndCommitments, s, sendCommitsReceiveChallenge)
	require.NoError(t, err, "failed to generate client proof, this is not expected")
	clientMessage := AuthenticationMessage{
		C:                        context,
		initialTagAndCommitments: *tagAndCommitments,
		P0:                       clientProof,
	}

	servMsg := ServerMessage{Request: clientMessage, Proofs: nil, Tags: nil, Sigs: nil, Indexes: nil}

	ServerProtocol(suite, &servMsg, servers[0])

	//Normal execution for correct proof
	data, err := servMsg.Proofs[0].ToBytes()
	require.NoError(t, err, "Cannot convert normal proof")
	require.NotNil(t, data, "Cannot convert normal proof")

	//Normal execution for correct misbehaving proof
	proof, _ := generateMisbehavingProof(suite, S[0], servers[0])
	data, err = proof.ToBytes()
	require.NoError(t, err, "Cannot convert misbehaving proof")
	require.NotNil(t, data, "Cannot convert misbehaving proof")
}
