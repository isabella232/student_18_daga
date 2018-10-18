package daga_login_test

//import (
//	"encoding/json"
//	"fmt"
//	"github.com/dedis/kyber"
//	"github.com/dedis/student_18_daga/daga_login"
//	"github.com/dedis/student_18_daga/sign/daga"
//	"github.com/stretchr/testify/assert"
//	"math/rand"
//	"testing"
//)
//
//// TODO when done, update test to use same marshalling methods than in the api/service instead of JSON
//
//var suite = daga.NewSuiteEC()
//
//func testServerProtocolsOnClientRequests(context daga.AuthenticationContext, servers []daga.Server) func(commits []kyber.Point)daga.Challenge {
//	//Simulate the transfer of the commitments t
//	//Encoding
//
//	sendCommitsReceiveChallenge := func(proverCommitments []kyber.Point)daga.Challenge {
//		_, Y := context.Members()
//		t := proverCommitments
//		nett, err := daga_login.NetEncodePoints(t)
//		if err != nil {
//			fmt.Printf("Error when encoding the commitments t\n%s\n", err)
//			return daga.Challenge{}
//		}
//		netdata, err := json.Marshal(nett)
//		if err != nil {
//			fmt.Printf("Cannot json marshal the commitments t\n%s\n", err)
//			return daga.Challenge{}
//		}
//		//Network transfer
//		//Decoding
//		var nettServer []daga_login.NetPoint
//		err = json.Unmarshal(netdata, &nettServer)
//		if err != nil || &nettServer == nil {
//			fmt.Printf("Cannot json unmarshal the commitments t\n%s\n", err)
//			return daga.Challenge{}
//		}
//		tserver, err := daga_login.NetDecodePoints(suite, nett)
//		if err != nil || tserver == nil {
//			fmt.Printf("Error in t decoding\n%s\n", err)
//			return daga.Challenge{}
//		}
//
//		//Server generation of the challenge upon receiving t
//		// FIXME if we want this to be a test at the very least don't assume that server and clients have same memory....
//		var j = rand.Intn(len(Y)) //Randomly selects the leader
//
//		//The commitments and the openings will be stored in the following array to ease their manipulation
//		//They will be transferred on the network according to the protocol below
//		var commits []daga.Commitment
//		var openings []kyber.Scalar
//		//Initialize both arrays
//		for num := 0; num < len(Y); num++ {
//			commits = append(commits, daga.Commitment{})
//			openings = append(openings, suite.Scalar().Zero())
//		}
//
//		//The leader asks other servers to generates commitments by publishing its own signed commitment
//		comlead, openlead, err := daga.GenerateCommitment(suite, &context, servers[j])
//		if err != nil {
//			fmt.Printf("Error when generating the leader commitment at server %d\n%s\n", j, err)
//			return daga.Challenge{}
//		}
//
//		commits[j] = *comlead
//		openings[j] = openlead
//
//		//Simulate transfer of comlead
//		sendCom, err := daga_login.CommitmentNetEncode(comlead)
//		if err != nil {
//			fmt.Printf("Error when encoding the commitment of the leader %d\n%s\n", j, err)
//			return daga.Challenge{}
//		}
//		netdata, err = json.Marshal(sendCom)
//		if err != nil {
//			fmt.Printf("Error when json marshal the commitment of the leader %d\n%s\n", j, err)
//			return daga.Challenge{}
//		}
//		//Network transfer
//		var rcvCom daga_login.NetCommitment
//		err = json.Unmarshal(netdata, &rcvCom)
//		if err != nil {
//			fmt.Printf("Error when json unmarshal the commitment of the leader %d\n%s\n", j, err)
//			return daga.Challenge{}
//		}
//		_, err = rcvCom.NetDecode(suite)
//		if err != nil {
//			fmt.Printf("Error when decoding the commitment of the leader %d\n%s\n", j, err)
//			return daga.Challenge{}
//		}
//
//		//Each server generates its commitment and send it to the leader
//		for num, server := range servers {
//			if num == j {
//				continue
//			}
//			com, open, e := daga.GenerateCommitment(suite, &context, server)
//			if e != nil {
//				fmt.Printf("Error when generating the commitment at server %d\n%s\n", num, e)
//				return daga.Challenge{}
//			}
//
//			commits[num] = *com
//			openings[num] = open
//
//			//Simulate the transfer of the commitment over the network
//			sendCom, e := daga_login.CommitmentNetEncode(com)
//			if e != nil {
//				fmt.Printf("Error when encoding the commitment at server %d\n%s\n", num, e)
//				return daga.Challenge{}
//			}
//			netdata, e = json.Marshal(sendCom)
//			if e != nil {
//				fmt.Printf("Error when json marshal the commitment at server %d\n%s\n", num, e)
//				return daga.Challenge{}
//			}
//			//Network transfer
//			var rcvCom daga_login.NetCommitment
//			e = json.Unmarshal(netdata, &rcvCom)
//			if e != nil {
//				fmt.Printf("Error when json unmarshal the commitment of server %d\n%s\n", num, e)
//				return daga.Challenge{}
//			}
//			_, e = rcvCom.NetDecode(suite)
//			if e != nil {
//				fmt.Printf("Error when decoding the commitment of server %d\n%s\n", num, e)
//				return daga.Challenge{}
//			}
//
//		}
//
//		//Once the leader has received all the commitments, it checks that they are of correct form and their signatures are valid
//		err = daga.VerifyCommitmentSignature(suite, &context, commits)
//		if err != nil {
//			fmt.Printf("Error when verifying the commitments\n%s\n", err)
//			return daga.Challenge{}
//		}
//
//		//When the verification is done, the leader asks the servers to reveal their openings by sending its own opening
//		//Simulate the transfer of the leader's opening over the network
//		sendOpen, err := daga_login.NetEncodeScalar(openlead)
//		if err != nil {
//			fmt.Printf("Error when encoding the opening of the leader %d\n", j)
//			return daga.Challenge{}
//		}
//		netdata, err = json.Marshal(sendOpen)
//		if err != nil {
//			fmt.Printf("Error when json marshal the opening of the leader %d\n", j)
//			return daga.Challenge{}
//		}
//		//Network transfer
//		var rcvOpen daga_login.NetScalar
//		err = json.Unmarshal(netdata, &rcvOpen)
//		if err != nil {
//			fmt.Printf("Error when json unmarshal the opening of the leader %d\n", j)
//			return daga.Challenge{}
//		}
//		_, err = rcvOpen.NetDecode(suite)
//		if err != nil {
//			fmt.Printf("Error when decoding the opening of the leader %d\n", j)
//			return daga.Challenge{}
//		}
//
//		//Each server ransfers its opening to the leader
//		for num := range servers {
//			if num == j {
//				continue
//			}
//
//			//Simulate the transfer of the opening over the network
//			sendOpen, e := daga_login.NetEncodeScalar(openings[num])
//			if e != nil {
//				fmt.Printf("Error when encoding the opening at server %d\n%s\n", num, e)
//				return daga.Challenge{}
//			}
//			netdata, e = json.Marshal(sendOpen)
//			if e != nil {
//				fmt.Printf("Error when json marshal the commitment at server %d\n%s\n", num, e)
//				return daga.Challenge{}
//			}
//			//Network transfer
//			var rcvOpen daga_login.NetScalar
//			e = json.Unmarshal(netdata, &rcvOpen)
//			if e != nil {
//				fmt.Printf("Error when json unmarshal the opening of server %d\n%s\n", num, e)
//				return daga.Challenge{}
//			}
//			//No need to check that this valkue is the same as the one before transfer, this is done in the test of the network functions in daga
//			_, e = rcvOpen.NetDecode(suite)
//			if e != nil {
//				fmt.Printf("Error when decoding the opening of server %d\n%s\n", num, e)
//				return daga.Challenge{}
//			}
//		}
//
//		//After receiving all the openings, server j veerifies them and initializes the challenge structure
//		challenge, err := daga.InitializeChallenge(suite, &context, commits, openings)
//		if err != nil {
//			fmt.Printf("Error when initializing the challenge\n%s\n", err)
//			return daga.Challenge{}
//		}
//
//		//Then it executes CheckUpdateChallenge
//		daga.CheckUpdateChallenge(suite, &context, challenge, servers[j])
//
//		//Next it sends this message to the next server
//		sendChall, err := daga_login.ChallengeCheckNetEncode(challenge)
//		if err != nil {
//			fmt.Printf("Error when encoding the challenge at the leader %d\n%s\n", j, err)
//			return daga.Challenge{}
//		}
//		netdata, err = json.Marshal(sendChall)
//		if err != nil {
//			fmt.Printf("Error when json marshal the challenge at leader %d\n%s\n", j, err)
//			return daga.Challenge{}
//		}
//		//Network transfer
//
//		//Each server receives the message
//		//then executes CheckUpdateChallenge
//		//and finally pass the challenge to the next one until it reaches the leader again
//		for shift := 1; shift <= len(Y); shift++ {
//			index := (j + shift) % (len(Y))
//			//Receive the previous message
//			var rcvChall daga_login.NetChallengeCheck
//			e := json.Unmarshal(netdata, &rcvChall)
//			if e != nil {
//				fmt.Printf("Error when json unmarshal the challenge at server %d\n%s\n", index, e)
//				return daga.Challenge{}
//			}
//			serverChallenge, e := rcvChall.NetDecode(suite)
//			if e != nil {
//				fmt.Printf("Error when decoding the challenge at server %d\n%s\n", index, e)
//				return daga.Challenge{}
//			}
//
//			//Executes CheckUpdateChallenge
//			daga.CheckUpdateChallenge(suite, &context, serverChallenge, servers[index])
//
//			//Encode and transfer the challenge to the next server
//			sendservChall, e := daga_login.ChallengeCheckNetEncode(serverChallenge)
//			if e != nil {
//				fmt.Printf("Error when encoding the challenge at server %d\n%s\n", index, e)
//				return daga.Challenge{}
//			}
//			netdata, e = json.Marshal(sendservChall)
//			if e != nil {
//				fmt.Printf("Error when json marshal the challenge at server %d\n%s\n", index, e)
//				return daga.Challenge{}
//			}
//			//Network transfer
//		}
//
//		//Finally the challenge is back at the leader
//		var rcvfinalChall daga_login.NetChallengeCheck
//		err = json.Unmarshal(netdata, &rcvfinalChall)
//		if err != nil {
//			fmt.Printf("Error when json unmarshal the challenge back at the leader %d\n%s\n", j, err)
//			return daga.Challenge{}
//		}
//		finalChallenge, err := rcvfinalChall.NetDecode(suite)
//		if err != nil {
//			fmt.Printf("Error when decoding the challenge at the leader %d\n%s\n", j, err)
//			return daga.Challenge{}
//		}
//
//		//It executes CheckUpdateChallenge to verify the correctness of the challenge
//		daga.CheckUpdateChallenge(suite, &context, finalChallenge, servers[j])
//
//		//Finalize the challenge before sending it to the client
//		clientChallenge, err := daga.FinalizeChallenge(&context, finalChallenge)
//		if err != nil {
//			fmt.Printf("Cannot finalize the challenge\n%s\n", err)
//		}
//
//		//The challenge is then sent back to the client
//		sendclientChall, err := daga_login.NetEncodeChallenge(clientChallenge)
//		if err != nil {
//			fmt.Printf("Error when encoding the client challenge at the leader %d\n%s\n", j, err)
//			return daga.Challenge{}
//		}
//		netdata, err = json.Marshal(sendclientChall)
//		if err != nil {
//			fmt.Printf("Error when json marshal the client challenge at leader %d\n%s\n", j, err)
//			return daga.Challenge{}
//		}
//		//Network transfer
//		var rcvclientChall daga_login.NetChallenge
//		err = json.Unmarshal(netdata, &rcvclientChall)
//		if err != nil {
//			fmt.Printf("Error when json unmarshal the challenge at client\n%s\n", err)
//			return daga.Challenge{}
//		}
//		masterChallenge, err := rcvclientChall.NetDecode(suite)
//		if err != nil {
//			fmt.Printf("Error when decoding the challenge at client\n%s\n", err)
//			return daga.Challenge{}
//		}
//		return *masterChallenge
//	}
//
//	return sendCommitsReceiveChallenge
//}
//
//// FIXME rewrite.. + again lots of redundant tests that add nothing except bullshitting the repo
//// TODO use assert..
//// FIXME move again in kyber/sign/daga nothing to do here
//func TestScenario(t *testing.T) {
//	// FIXME remember to "implement" the context generation,
//	//Number of clients
//	c := 20
//	//Number of servers
//	s := 10
//	serverKeys := make([]kyber.Scalar, s)  // all nil => keys will be drawn at random
//	clients, servers, serviceContext, err := daga.GenerateContext(suite, c, serverKeys)
//	if err != nil {
//		fmt.Printf("Error in while creating context\n%s\n", err)
//		return
//	}
//
//	//Simulate the transfer of the context from the service to the client
//	//Encoding
//	netServiceContext, err := daga_login.NetEncodeContext(serviceContext)
//	if err != nil {
//		fmt.Printf("Error in context encoding\n%s\n", err)
//		return
//	}
//	netdata, err := json.Marshal(netServiceContext)
//	if err != nil {
//		fmt.Printf("Cannot json marshal the context\n%s\n", err)
//		return
//	}
//	//Network transfer
//	//Decoding
//	var netContext daga_login.NetContextEd25519
//	err = json.Unmarshal(netdata, &netContext)
//	if err != nil || &netContext == nil {
//		fmt.Printf("Cannot json unmarshal the context\n%s\n", err)
//		return
//	}
//	context, err := netContext.NetDecode(suite)
//	if err != nil {
//		fmt.Printf("Error in context decoding\n%s\n", err)
//		return
//	}
//
//	X, Y := serviceContext.Members()
//
//	//Client's protocol
//	var i = rand.Intn(len(X))
//	sendCommitsReceiveChallenge := testServerProtocolsOnClientRequests(*context, servers)
//	msg, err := daga.NewAuthenticationMessage(suite, *context, clients[i], sendCommitsReceiveChallenge)
//	assert.NoError(t, err)
//
//	//Arbitrarily select a server to send the message to
//	j := rand.Intn(len(Y))
//
//	//Simulate the transfer of the client message to the server
//	sendclientMsg, err := daga_login.AuthenticationMessageNetEncode(msg)
//	if err != nil {
//		fmt.Printf("Error when encoding the client message\n%s\n", err)
//		return
//	}
//	netdata, err = json.Marshal(sendclientMsg)
//	if err != nil {
//		fmt.Printf("Error when json marshal the client message\n%s\n", err)
//		return
//	}
//	//Network transfer
//	var rcvclientMsg daga_login.NetClientMessage
//	err = json.Unmarshal(netdata, &rcvclientMsg)
//	if err != nil {
//		fmt.Printf("Error when json unmarshal the client message\n%s\n", err)
//		return
//	}
//	_, err = rcvclientMsg.NetDecode(suite)
//	if err != nil {
//		fmt.Printf("Error when decoding the client message\n%s\n", err)
//		return
//	}
//
//	//This server initialize the server message with the request from the client
//	msgServ, err := daga.InitializeServerMessage(msg)
//	if err != nil {
//		fmt.Printf("Error when initializing the server message\n%s\n", err)
//		return
//	}
//
//	for shift := range servers {
//		index := (j + shift) % len(Y)
//		e := daga.ServerProtocol(suite, context, msgServ, servers[index])
//		if e != nil {
//			fmt.Printf("Error in the server protocol at server %d, shift %d:\n%s\n", (j+shift)%len(Y), shift, e)
//			return
//		}
//		//The server pass the massage to the next one
//		//If this is the last server, it broadcasts it to all the servers and the client
//		sendservMsg, e := daga_login.ServerMessageNetEncode(suite, msgServ)
//		if e != nil {
//			fmt.Printf("Error when encoding the server message at server %d\n%s\n", index, e)
//			return
//		}
//		netdata, e = json.Marshal(sendservMsg)
//		if e != nil {
//			fmt.Printf("Error when json marshal the server message at server %d\n%s\n", index, e)
//			return
//		}
//		//Network transfer
//		var rcvservMsg daga_login.NetServerMessage
//		e = json.Unmarshal(netdata, &rcvservMsg)
//		if e != nil {
//			fmt.Printf("Error when json unmarshal the server message at server %d\n%s\n", index, e)
//			return
//		}
//		_, e = rcvservMsg.NetDecode(suite)
//		if e != nil {
//			fmt.Printf("Error when decoding the server message at server %d\n%s\n", index, e)
//			return
//		}
//	}
//
//	//Once the message was completed by all the servers,
//	//it is sent back to the client.
//	//The clients then verifies the signatures then the proofs and gets its final linkage tag for this context
//	Tf, err := daga.GetFinalLinkageTag(suite, context, *msgServ)
//	if err != nil {
//		fmt.Printf("Cannot verify server message:\n%s", err)
//		return
//	} else {
//		//A Null value means that the authentication is rejected
//		if Tf.Equal(suite.Point().Null()) {
//			fmt.Printf("Authentication rejected\n")
//			return
//		}
//	}
//
//	return
//}
