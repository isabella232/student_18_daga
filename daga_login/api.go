package daga_login

/*
The api.go defines the methods that can be called from the outside. Most
of the methods will take a roster so that the service knows which nodes
it should work with.

This part of the service runs on the client or the app.
*/

import (
	"errors"
	"github.com/dedis/cothority"
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
// TODO see how this i will be handled...when building the service/protocoles conodes etc..
func NewClient(i int, s kyber.Scalar) (*Client, error) {
	if dagaClient, err := daga.NewClient(suite, i, s); err != nil {
		return nil, err
	} else {
		return &Client{
			Client: dagaClient,
			// FIXME QUESTION: here not sure what is Suite, should I substitute mine ?
			onet: onet.NewClient(cothority.Suite, ServiceName),
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
// FIXME add a linkageTag type in kyber.daga
// TODO mybe make the authcontext an interface + type like client and then here create a Context that embed roster + daga.context (mhh bad idea I would say)
func (c Client) Login(context daga.AuthenticationContext, r *onet.Roster) (kyber.Point, error) {
	// TODO see if context big enough to justify transforming the parameter into *authenticationContext
	// TODO FIXME think where/when/how check context validity (points/keys don't have small order, generators are generators etc..)

	// abstraction of remote server for PKclient, sendCommitsReceiveChallenge
	// FIXME draw daga server at random from context ! not from all conodes in roster => need helpers and mapping
	PKclientVerifier := c.newPKclientVerifier(r.RandomServerIdentity())

	if M0, err := daga.NewAuthenticationMessage(suite, context, c, PKclientVerifier); err != nil {
		return nil, errors.New("failed to build new authentication message: " + err.Error())
	} else {
		log.Panic("c.Login: remaining parts not implemented")
		reply := &daga.ServerMessage{}
		err := c.onet.SendProtobuf(r.RandomServerIdentity(), M0, reply) // god I miss WCF.NET...
		if err != nil {
			return nil, err
		}
		// TODO wait for serverprotocol to complete
		if Tf, err := daga.GetFinalLinkageTag(suite, &context, *reply); err != nil {
			return nil, errors.New("failed to extract final linkage tag from server reply: " + err.Error())
		} else {
			return Tf, nil
		}
	}
}

// send PKclient commitments and receive master challenge
func (c Client) pKClient(dst *network.ServerIdentity, proverCommitments []kyber.Point) daga.Challenge {
	commitments, err := NetEncodePoints(proverCommitments)
	if err != nil {
		log.Panic("error encoding commitments:", err)
		return daga.Challenge{}
	}
	log.Lvl4("Sending PKclient commitments to", dst)
	reply := NetChallenge{}
	// QUESTION see if I need to "cast" them to the type alias registered in struct
	request := &PKclientCommitments{Data:commitments}
	err = c.onet.SendProtobuf(dst, request, &reply)
	if err != nil {
		log.Panic("error sending commitments to", dst, ":", err)
		return daga.Challenge{}
	}
	challenge, err := reply.NetDecode(suite)
	if err != nil {
		log.Panic("error decoding Challenge from", dst, ":", err)
		return daga.Challenge{}
	}
	return *challenge
}

// Clock chooses one server from the Roster at random. It
// sends a Clock to it, which is then processed on the server side
// via the code in the service package.
//
// Clock will return the time in seconds it took to run the protocol.
func (c Client) Clock(r *onet.Roster) (*ClockReply, error) {
	dst := r.RandomServerIdentity()
	log.Lvl4("Sending message to", dst)
	reply := &ClockReply{}
	err := c.onet.SendProtobuf(dst, &Clock{r}, reply)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

// Count will return the number of times `Clock` has been called on this
// service-node.
func (c Client) Count(si *network.ServerIdentity) (int, error) {
	reply := &CountReply{}
	err := c.onet.SendProtobuf(si, &Count{}, reply)
	if err != nil {
		return -1, err
	}
	return reply.Count, nil
}
