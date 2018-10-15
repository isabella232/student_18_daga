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

// performs the client protocol and proof of knowledge, to generate a new authentication message
func (c Client) NewAuthenticationMessage(context daga.AuthenticationContext, r *onet.Roster) (daga.AuthenticationMessage, error) {
	// TODO rename
	// TODO see if context big enough to justify transforming the parameter into *authenticationContext
	// TODO FIXME think where/when/how check context validity (points/keys don't have small order, generators are generators etc..)

	// TODO server selection (at random) and circuit establishment "channel" from/to server (use roster infos etc..)


	// TODO  => using onet/cothority facilities
	// TODO net encode/decode data (if needed/not provided by onet/cothority)
	// TODO see cothority template, on reception of a challenge message (to define) from the network pipe it into the pullChallenge chan => register an handler that do that
	// TODO  ''  , on reception of the commitments from the pushCommitments channel pipe them to the remote server over the network
	// TODO see relevant comments in newClientProof

	var pushCommitments chan []kyber.Point
	var pullChallenge chan daga.Challenge

	// TODO why

	if M0, err := daga.NewAuthenticationMessage(suite, context, c, pushCommitments, pullChallenge); err != nil {
		return daga.AuthenticationMessage{}, errors.New("failed to build new authentication message: " + err.Error())
	} else {
		return *M0, nil
	}
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
