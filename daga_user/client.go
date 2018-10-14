package daga_user

import (
	"errors"
	"github.com/dedis/kyber"
	"github.com/dedis/student_18_daga/sign/daga"
)

// TODO QUESTION decide whether to put Client in kyber or not (make it a "user" of kyber.daga functions)

var suite = daga.NewSuiteEC()

// Client is used to store a daga.Client and TODO whatever I'll need but is not needed by kyber.daga
type Client struct {
	daga.Client
}

// NewClient is used to initialize a new client with a given index
// If no private key is given, a random one is chosen
// TODO see how this i will be handled...when building the service/protocoles conodes etc..
func NewClient(i int, s kyber.Scalar) (*Client, error) {
	if dagaClient, err := daga.NewClient(suite, i, s); err != nil {
		return nil, err
	} else {
		return &Client{
			dagaClient,
		}, nil
	}
}

// performs the client protocol and proof of knowledge, to generate a new authentication message
func (c Client) NewAuthenticationMessage(context daga.AuthenticationContext) (daga.AuthenticationMessage, error) {
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


