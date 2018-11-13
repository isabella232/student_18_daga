package daga_login

/*
This part of the service runs on the client or the app.
*/

import (
	"errors"
	"fmt"
	"github.com/dedis/kyber"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/dedis/student_18_daga/sign/daga"
)

// ServiceName is used for registration on the onet.
const ServiceName = "daga"

var suite = daga.NewSuiteEC()

// TODO maybe belongs to daga or maybe doesn't deserve its type..
type PKclientVerifier func([]kyber.Point) (daga.Challenge, error)

// return a function that wraps a PKClient API call to `dst` under `context`. the returned function accept PKClient commitments as parameter
// and returns the master challenge.
func (c Client) newPKclientVerifier(context Context, dst *network.ServerIdentity) PKclientVerifier {
	// poor man's curry
	sendCommitsReceiveChallenge := func(proverCommitments []kyber.Point) (daga.Challenge, error) {
		return c.pKClient(dst, context, proverCommitments)
	}
	return sendCommitsReceiveChallenge
}

// performs the client protocols and proof of knowledge, to generate a new authentication message,
// send it and extract final linkage tag after completion of the auth. process
func (c Client) Auth(context Context) (kyber.Point, error) {
	// TODO FIXME QUESTION think where/when/how check context validity (points/keys don't have small order, generators are generators etc..)

	// abstraction of remote servers/verifiers for PKclient, it is a function that wrap an API call to PKclient
	PKclientVerifier := c.newPKclientVerifier(context, context.RandomServerIdentity())

	// build daga auth. message
	if M0, err := daga.NewAuthenticationMessage(suite, context, c, PKclientVerifier); err != nil {
		return nil, errors.New("failed to build new authentication message: " + err.Error())
	} else {
		// send it to random server (API call to Auth)
		request := Auth(*NetEncodeAuthenticationMessage(context, *M0))
		reply := AuthReply{}
		dst := context.RandomServerIdentity()
		if err := c.Onet.SendProtobuf(dst, &request, &reply); err != nil {
			return nil, fmt.Errorf("error sending auth. request to %s : %s", dst, err)
		}
		// decode reply
		serverMsg, context, err := NetServerMessage(reply).NetDecode()
		if err != nil {
			return nil, fmt.Errorf("error decoding auth. reply from %s : %s", dst, err)
		}
		// TODO FIXME QUESTION check that received context match sent context
		// extract final linkage tag
		if Tf, err := daga.GetFinalLinkageTag(suite, context, *serverMsg); err != nil {
			return nil, errors.New("failed to extract final linkage tag from server reply: " + err.Error())
		} else {
			return Tf, nil
		}
	}
}

// send PKclient commitments and receive master challenge
func (c Client) pKClient(dst *network.ServerIdentity, context Context, commitments []kyber.Point) (daga.Challenge, error) {
	log.Lvl3("pKClient, sending commitments to: ", dst)
	request := PKclientCommitments{
		Commitments: commitments,
		Context:     context,
	}
	reply := PKclientChallenge{}
	err := c.Onet.SendProtobuf(dst, &request, &reply)
	if err != nil {
		return daga.Challenge{}, fmt.Errorf("pKClient, error sending commitments to %s : %s", dst, err)
	}
	log.Lvl3("pKClient, received master challenge from: ", dst)
	return daga.Challenge(reply), nil
}
