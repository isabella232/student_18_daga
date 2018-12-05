package dagacothority

/*
TODO
*/

import (
	"errors"
	"fmt"
	"github.com/dedis/kyber"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/dedis/student_18_daga/sign/daga"
)

// ServiceName is used for registration on the onet.
const ServiceName = "daga"

var suite = daga.NewSuiteEC()

// CreateContext issue a CreateContext call to the daga cothority specified by roster.
// (API call to the CreateContext endpoint of a random server in roster, that will,
// if accepted, trigger the dagacontextgeneration protocol with the nodes in roster)
// TODO documente scenario/business use case, by products etc.., e.g. now after such call the daga cothority start serving (= processing auth request under) the context
func (ac AdminCLient) CreateContext(subscribers []kyber.Point, roster *onet.Roster) (*Context, error) {
	// build request
	request := CreateContext{
		ServiceID:       ac.ServiceID,
		SubscribersKeys: subscribers,
		DagaNodes:       roster,
		Signature:       make([]byte, 32), // TODO openPGP sig or other way to auth. admin of 3rd-party service etc..
	}
	reply := CreateContextReply{}

	// send to random server in cothority
	dst := roster.RandomServerIdentity()
	if err := ac.SendProtobuf(dst, &request, &reply); err != nil {
		return nil, fmt.Errorf("error sending CreateContext request to %s : %s", dst, err)
	}

	return &reply.Context, nil
}

// NewPKclientVerifier returns a function that wraps a PKClient API call to `dst` under `context`.
// the returned function accept PKClient commitments as parameter
// and returns the master challenge.
func (c Client) NewPKclientVerifier(context Context, dst *network.ServerIdentity) daga.PKclientVerifier {
	// poor man's curry
	sendCommitsReceiveChallenge := func(proverCommitments []kyber.Point) (daga.Challenge, error) {
		return c.pKClient(dst, context, proverCommitments)
	}
	return sendCommitsReceiveChallenge
}

// Auth performs the client protocol and proof of knowledge, to :
// - generate a new authentication message,
// - send it (API call to Auth endpoint of a random server)
// - finally extract the final linkage tag after completion of the auth. process
func (c Client) Auth(context Context) (kyber.Point, error) {
	// TODO FIXME QUESTION think where/when/how check context validity (points/keys don't have small order, generators are generators etc..)

	// abstraction of remote servers/verifiers for PKclient, it is a function that wrap an API call to PKclient
	PKclientVerifier := c.NewPKclientVerifier(context, context.Roster.RandomServerIdentity())

	// build daga auth. message
	if M0, err := daga.NewAuthenticationMessage(suite, context, c, PKclientVerifier); err != nil {
		return nil, errors.New("failed to build new authentication message: " + err.Error())
	} else {
		// send it to random server (API call to Auth)
		request := *NetEncodeAuthenticationMessage(context, *M0)
		reply := AuthReply{}
		dst := context.Roster.RandomServerIdentity()
		if err := c.Onet.SendProtobuf(dst, &request, &reply); err != nil {
			return nil, fmt.Errorf("error sending auth. request to %s : %s", dst, err)
		}
		// decode reply
		serverMsg, context := reply.NetDecode()
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
	return *reply.NetDecode(), nil
}
