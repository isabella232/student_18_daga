package daga_login_test

import (
	"fmt"
	"github.com/dedis/kyber"
	"github.com/dedis/student_18_daga/sign/daga"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"testing"
)

// TODO when done, maybe update test to use same marshalling methods than in the api/service instead of removing those ops
// for now I'm convinced that the thing is "working" don't lose time make this run again until useful..I'm not testing the codecs nor the network
var suite = daga.NewSuiteEC()

func testServerProtocolsOnClientRequests(context daga.AuthenticationContext, servers []daga.Server) func(commits []kyber.Point) (daga.Challenge, error) {
	//Simulate the transfer of the commitments t
	//Encoding

	sendCommitsReceiveChallenge := func(proverCommitments []kyber.Point) (daga.Challenge, error) {
		_, Y := context.Members()

		//Network transfer
		//Decoding
		// I'm not testing the network marshall lib..

		//Server generation of the challenge upon receiving t
		var j = rand.Intn(len(Y)) //Randomly selects the leader

		//The commitments and the openings will be stored in the following array to ease their manipulation
		//They will be transferred on the network according to the protocols below
		var commits []daga.ChallengeCommitment
		var openings []kyber.Scalar
		//Initialize both arrays
		for num := 0; num < len(Y); num++ {
			commits = append(commits, daga.ChallengeCommitment{})
			openings = append(openings, suite.Scalar().Zero())
		}

		//The leader asks other servers to generates commitments by publishing its own signed commitment
		comlead, openlead, err := daga.NewChallengeCommitment(suite, servers[j])
		if err != nil {
			return daga.Challenge{}, fmt.Errorf("error when generating the leader commitment at server %d\n%s\n", j, err)
		}

		commits[j] = *comlead
		openings[j] = openlead

		//Simulate transfer of comlead

		//Each server generates its commitment and send it to the leader
		for num, server := range servers {
			if num == j {
				continue
			}
			com, open, e := daga.NewChallengeCommitment(suite, server)
			if e != nil {
				return daga.Challenge{}, fmt.Errorf("error when generating the commitment at server %d\n%s\n", num, e)
			}
			commits[num] = *com
			openings[num] = open
			//Simulate the transfer of the commitment over the network
		}

		//Once the leader has received all the commitments, it checks that they are of correct form and their signatures are valid
		err = daga.VerifyChallengeCommitmentsSignatures(suite, context, commits)
		if err != nil {
			return daga.Challenge{}, fmt.Errorf("error when verifying the commitments\n%s\n", err)
		}

		//When the verification is done, the leader asks the servers to reveal their openings by sending its own opening
		//Simulate the transfer of the leader's opening over the network

		//Each server ransfers its opening to the leader
		for num := range servers {
			if num == j {
				continue
			}

			//Simulate the transfer of the opening over the network

			//Network transfer
		}

		//After receiving all the openings, server j verifies them and initializes the challenge structure
		challenge, err := daga.InitializeChallenge(suite, context, commits, openings)
		if err != nil {
			return daga.Challenge{}, fmt.Errorf("error when initializing the challenge\n%s\n", err)
		}

		//Then it executes CheckUpdateChallenge
		daga.CheckUpdateChallenge(suite, context, challenge, proverCommitments, servers[j])

		//Next it sends this message to the next server

		//Network transfer

		//Each server receives the message
		//then executes CheckUpdateChallenge
		//and finally pass the challenge to the next one until it reaches the leader again
		for shift := 1; shift <= len(Y); shift++ {
			index := (j + shift) % (len(Y))
			//Receive the previous message

			//Executes CheckUpdateChallenge
			daga.CheckUpdateChallenge(suite, context, challenge, proverCommitments, servers[index])

			//Encode and transfer the challenge to the next server

			//Network transfer
		}

		//Finally the challenge is back at the leader

		//It executes CheckUpdateChallenge to verify the correctness of the challenge
		daga.CheckUpdateChallenge(suite, context, challenge, proverCommitments, servers[j])

		//Finalize the challenge before sending it to the client
		clientChallenge, err := daga.FinalizeChallenge(context, challenge)
		if err != nil {
			return clientChallenge, fmt.Errorf("Cannot finalize the challenge\n%s\n", err)
		}

		//The challenge is then sent back to the client
		return clientChallenge, nil
	}
	return sendCommitsReceiveChallenge
}

// FIXME rewrite.. + again lots of redundant tests that add nothing except bullshitting the repo
// TODO use assert..
// FIXME move again in kyber/sign/daga nothing to do here
func TestScenario(t *testing.T) {
	//Number of clients
	c := 20
	//Number of servers
	s := 10
	serverKeys := make([]kyber.Scalar, s) // all nil => keys will be drawn at random
	clients, servers, serviceContext, err := daga.GenerateContext(suite, c, serverKeys)
	if err != nil {
		fmt.Printf("Error in while creating context\n%s\n", err)
		return
	}

	//Simulate the transfer of the context from the service to the client
	//Encoding
	//Network transfer
	//Decoding

	X, Y := serviceContext.Members()

	//Client's protocols
	var i = rand.Intn(len(X))
	sendCommitsReceiveChallenge := testServerProtocolsOnClientRequests(serviceContext, servers)
	msg, err := daga.NewAuthenticationMessage(suite, serviceContext, clients[i], sendCommitsReceiveChallenge)
	assert.NoError(t, err)

	//Arbitrarily select a server to send the message to
	j := rand.Intn(len(Y))

	//Simulate the transfer of the client message to the server

	//Network transfer

	//This server initialize the server message with the request from the client
	msgServ, err := daga.InitializeServerMessage(msg)
	if err != nil {
		fmt.Printf("Error when initializing the server message\n%s\n", err)
		return
	}

	for shift := range servers {
		index := (j + shift) % len(Y)
		e := daga.ServerProtocol(suite, msgServ, servers[index])
		if e != nil {
			fmt.Printf("Error in the server protocols at server %d, shift %d:\n%s\n", (j+shift)%len(Y), shift, e)
			return
		}
		//The server pass the massage to the next one
		//If this is the last server, it broadcasts it to all the servers and the client

		//Network transfer

	}

	//Once the message was completed by all the servers,
	//it is sent back to the client.
	//The clients then verifies the signatures then the proofs and gets its final linkage tag for this context
	Tf, err := daga.GetFinalLinkageTag(suite, serviceContext, *msgServ)
	if err != nil {
		fmt.Printf("Cannot verify server message:\n%s", err)
		return
	} else {
		//A Null value means that the authentication is rejected
		if Tf.Equal(suite.Point().Null()) {
			fmt.Printf("Authentication rejected\n")
			return
		}
	}

	return
}
