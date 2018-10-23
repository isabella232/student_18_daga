package daga_login

/*
The api.go defines the methods that can be called from the outside. Most
of the methods will take a roster so that the service knows which nodes
it should work with.

This part of the service runs on the client or the app.
*/

import (
	"errors"
	"github.com/dedis/kyber"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/dedis/student_18_daga/sign/daga"
)

// ServiceName is used for registration on the onet.
const ServiceName = "daga_login"

var suite = daga.NewSuiteEC()

// Client is used to store a daga.Client, an onet.Client and TODO whatever I'll need but is not needed by kyber.daga
type Client struct {
	daga.Client
	onet *onet.Client
}

// NewClient is used to initialize a new client with a given index
// If no private key is given, a random one is chosen
func NewClient(i int, s kyber.Scalar) (*Client, error) {
	if dagaClient, err := daga.NewClient(suite, i, s); err != nil {
		return nil, err
	} else {
		return &Client{
			Client: dagaClient,
			onet: onet.NewClient(suite, ServiceName),
		}, nil
	}
}

type PKclientVerifier func([]kyber.Point)daga.Challenge
func (c Client) newPKclientVerifier(dst *network.ServerIdentity) PKclientVerifier {
	// poor man's curry
	sendCommitsReceiveChallenge := func(proverCommitments []kyber.Point)daga.Challenge {
		return c.pKClient(dst, proverCommitments)
	}
	return sendCommitsReceiveChallenge
}

// performs the client protocol and proof of knowledge, to generate a new authentication message, send it and extract final linkage tag after completion of the auth. process
// TODO mybe make the authcontext an interface + type like client and then here create a Context that embed roster + daga.context (mhh bad idea I would say)
// QUESTION But I DO need a way/informations to contact every server from every server !!
func (c Client) Login(context daga.AuthenticationContext, r *onet.Roster) (kyber.Point, error) {
	// TODO FIXME think where/when/how check context validity (points/keys don't have small order, generators are generators etc..)
	// abstraction of remote server/verifier for PKclient, sendCommitsReceiveChallenge
	// FIXME draw daga server at random from context ! not from all conodes in roster => need helpers and mapping
	PKclientVerifier := c.newPKclientVerifier(r.RandomServerIdentity())

	if M0, err := daga.NewAuthenticationMessage(suite, context, c, PKclientVerifier); err != nil {
		return nil, errors.New("failed to build new authentication message: " + err.Error())
	} else {
		request := NetEncodeAuthenticationMessage(M0)
		reply := NetServerMessage{}

		// QUESTION FIXME draw daga server at random from context ! not from all conodes in roster => need helpers and mapping
		dst := r.RandomServerIdentity()
		err = c.onet.SendProtobuf(dst, request, &reply)
		if err != nil {
			log.Panic("error sending auth. request to", dst, ":", err)
			return nil, err
		}
		serverMsg, err := reply.NetDecode(suite)
		if err != nil {
			log.Panic("error decoding auth. reply from", dst, ":", err)
			return nil, err
		}
		log.Panic("c.Login: remaining parts not implemented")

		if Tf, err := daga.GetFinalLinkageTag(suite, &context, *serverMsg); err != nil {
			return nil, errors.New("failed to extract final linkage tag from server reply: " + err.Error())
		} else {
			return Tf, nil
		}
	}
}

// send PKclient commitments and receive master challenge
func (c Client) pKClient(dst *network.ServerIdentity, commitments []kyber.Point) daga.Challenge {
	log.Lvl4("PKclient, sending commitments to:", dst)
	reply := PKclientChallenge{}
	request := PKclientCommitments{Data:commitments}
	err := c.onet.SendProtobuf(dst, &request, &reply)
	if err != nil {
		log.Panic("PKclient, error sending commitments to", dst, ":", err)
		return daga.Challenge{}
	}
	log.Lvl4("PKclient, received master challenge from:", dst)
	return daga.Challenge(reply)
}