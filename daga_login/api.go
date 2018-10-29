package daga_login

/*
The api.go defines the methods that can be called from the outside. Most
of the methods will take a roster so that the service knows which nodes
it should work with.

This part of the service runs on the client or the app.
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
const ServiceName = "daga_login" // FIXME rename to daga, for now there is no "login"

var suite = daga.NewSuiteEC()

// Client implements the daga.Client interface and embeds an onet.Client and TODO whatever I'll need but is not needed by kyber.daga
type Client struct {
	daga.Client
	// TODO if time, one of the point of embedding anon interface is if you want to override some of the methods
	// (type has now access to a parent struct that implement interface and implements interface too through promotion), that was what I had in mind,
	// ideally would need to rewrite the daga functions to be methods, add them to the interface
	// and here override some of them where needed to wrap them in the onet framework
	// same mechanisms as extend / super in OO languages
	// + by doing so can pass any struct that implement daga.Client when creating Client => can test/mock/stub etc..
	onet *onet.Client
}

// NewClient is used to initialize a new Client with a given index
// If no private key is given, a random one is chosen
func NewClient(i int, s kyber.Scalar) (*Client, error) {
	if dagaClient, err := daga.NewClient(suite, i, s); err != nil {
		return nil, err
	} else {
		return &Client{
			Client: dagaClient,
			onet:   onet.NewClient(suite, ServiceName),
		}, nil
	}
}

// Context implements the daga.AuthenticationContext interface
// and embed a corresponding Onet roster (how to reach the DAGA servers)
type Context struct {
	daga.AuthenticationContext
	onet.Roster
}

// returns a pointer to newly allocated Context struct initialized with the provided daga.AuthenticationContext
// and a roster containing only the servers of fullRoster that are part of the daga.AuthenticationContext.
// additionally
// checks that the provided fullRoster contains at least one ServerIdentity for each DAGA server in dagaContext
func NewContext(dagaContext daga.AuthenticationContext, fullRoster onet.Roster) (*Context, error) {

	// TODO/FIXME validate dagaContext (can use daga function that build context for that purpose)

	// maps public keys to the full identity
	serverId := make(map[string]*network.ServerIdentity, len(fullRoster.List))
	for _, sid := range fullRoster.List {
		serverId[sid.Public.String()] = sid
	}

	// builds new (sub)-roster
	_, Y := dagaContext.Members()
	dagaList := make([]*network.ServerIdentity, 0, len(Y))
	for _, pubKey := range Y {
		if sid, ok := serverId[pubKey.String()]; ok {
			dagaList = append(dagaList, sid)
		} else {
			return nil, fmt.Errorf("NewContext: provided roster doesn't contain an Identity for daga server with publicKey: %s", pubKey.String())
		}
	}
	dagaRoster := onet.NewRoster(dagaList)
	return &Context{
		AuthenticationContext: dagaContext,
		Roster:                *dagaRoster,
	}, nil
}

// to be used by actors upon reception of request/reply to verify that it is part of same auth.context that was requested/is accepted.
// in general for DAGA to work we need to check/enforce same order but this function is only to check that the context is the "same"
// that one of our accepted context (TODO maybe not useful but maybe useful, remember when benchmarking..).
// after the check done, to proceed remember to keep context that is in message/request/reply for all computations.
func (c Context) Equals(other Context) bool {
	// TODO consider moving this in kyber daga
	containsSameElems := func(a, b []kyber.Point) bool {
		// use maps to mimic set, first traverse first slice and populate map
		// then traverse second slice checking if value present in map and indeed equal (stringEq ==> eq)
		if len(a) != len(b) {
			return false
		}
		set := make(map[string]struct{}, len(a))
		exist := struct{}{}
		for _, p := range a {
			set[p.String()] = exist
		}
		for _, p := range b {
			if _, present := set[p.String()]; !present {
				return false
			}
		}
		return true
	}

	//if reflect.DeepEqual(c, other) {  // TODO check if it is useful... maybe can never work..
	//	return true
	//} else {
	X1, Y1 := c.Members()
	X2, Y2 := other.Members()
	return containsSameElems(X1, X2) &&
		containsSameElems(Y1, Y2) &&
		containsSameElems(c.ClientsGenerators(), other.ClientsGenerators()) &&
		containsSameElems(c.ServersSecretsCommitments(), other.ServersSecretsCommitments())
	// TODO QUESTION FIXME should I compare rosters (and then how ? actual content or IDs..) ? what can go wrong if same daga context and different rosters
	// IMO nothing since if another server has knowledge of key then ... either this is bad but out of our reach or maybe legitimate use to balance workload ??
	//}
}

func (c Context) ServerIndexOf(publicKey kyber.Point) (int, error) {
	_, Y := c.Members()
	return IndexOf(Y, publicKey)
}

type PKclientVerifier func([]kyber.Point) daga.Challenge

func (c Client) newPKclientVerifier(context Context, dst *network.ServerIdentity) PKclientVerifier {
	// poor man's curry
	sendCommitsReceiveChallenge := func(proverCommitments []kyber.Point) daga.Challenge {
		return c.pKClient(dst, context, proverCommitments)
	}
	return sendCommitsReceiveChallenge
}

// performs the client protocols and proof of knowledge, to generate a new authentication message, send it and extract final linkage tag after completion of the auth. process
func (c Client) Auth(context Context) (kyber.Point, error) {
	// TODO FIXME think where/when/how check context validity (points/keys don't have small order, generators are generators etc..)

	// abstraction of remote server/verifier for PKclient, it is a function that wrap an API call to PKclient
	PKclientVerifier := c.newPKclientVerifier(context, context.RandomServerIdentity())

	// build daga auth. message
	if M0, err := daga.NewAuthenticationMessage(suite, context, c, PKclientVerifier); err != nil {
		return nil, errors.New("failed to build new authentication message: " + err.Error())
	} else {
		// send it to random server (API call to Auth)
		request := Auth(*NetEncodeAuthenticationMessage(context, M0))
		reply := NetServerMessage{}

		dst := context.RandomServerIdentity()
		err = c.onet.SendProtobuf(dst, &request, &reply)
		if err != nil {
			log.Panic("error sending auth. request to", dst, ":", err)
			return nil, err
		}
		serverMsg, context, err := reply.NetDecode()
		if err != nil {
			log.Panic("error decoding auth. reply from", dst, ":", err)
			return nil, err
		}
		// TODO FIXME check that received context match sent context

		if Tf, err := daga.GetFinalLinkageTag(suite, context.AuthenticationContext, *serverMsg); err != nil {
			return nil, errors.New("failed to extract final linkage tag from server reply: " + err.Error())
		} else {
			return Tf, nil
		}
	}
}

// send PKclient commitments and receive master challenge
func (c Client) pKClient(dst *network.ServerIdentity, context Context, commitments []kyber.Point) daga.Challenge {
	log.Lvl4("PKclient, sending commitments to:", dst)
	reply := PKclientChallenge{}
	request := PKclientCommitments{
		Data:    commitments,
		Context: *context.NetEncode(),
	}
	err := c.onet.SendProtobuf(dst, &request, &reply)
	if err != nil {
		log.Panic("PKclient, error sending commitments to", dst, ":", err)
		return daga.Challenge{}
	}
	log.Lvl4("PKclient, received master challenge from:", dst)
	return daga.Challenge(reply)
}
