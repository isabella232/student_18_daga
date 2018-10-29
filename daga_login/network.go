package daga_login

import (
	"errors"
	"fmt"
	"github.com/dedis/kyber"
	"github.com/dedis/onet"
	"github.com/dedis/student_18_daga/sign/daga"
)

// contain net wrappers around the kyber.daga datastructures and

// TODO QUESTION ask, dumb IMO but feel kind of bad exporting things that are intended to be immutable so the in between solution is to have a separate struct
// TODO ~messy IMO, how to do it in a idiomatic and educated way ?

/*NetMembers provides a net compatible representation of the Members struct*/
type NetMembers struct {
	X []kyber.Point
	Y []kyber.Point
}

// NetContext provides a net compatible representation of the Context struct
// (which has interface field (daga.AuthenticationContext))
type NetContext struct {
	Roster onet.Roster
	G      NetMembers
	R      []kyber.Point
	H      []kyber.Point
}

// to represent a daga.Client (which is an interface)
// used only to dump client to disk while developing for now
type NetClient struct {
	PrivateKey kyber.Scalar
	Index      int
}

// to represent a daga.Server (which is an interface)
// used only to dump server to disk while developing for now
type NetServer struct {
	PrivateKey     kyber.Scalar
	Index          int
	PerRoundSecret kyber.Scalar
}

// NetAuthenticationMessage provides a net compatible representation of the daga.AuthenticationMessage struct
// (which embeds a context which has interface fields)
type NetAuthenticationMessage struct {
	Context  NetContext
	SCommits []kyber.Point
	T0       kyber.Point
	Proof    daga.ClientProof
}

// NetServerMessage provides a net compatible representation of the daga.ServerMessage struct
// (which embeds an auth message struct which embeds a context which ..)
type NetServerMessage struct {
	Request NetAuthenticationMessage
	Tags    []kyber.Point
	Proofs  []daga.ServerProof
	Indexes []int
	Sigs    []daga.ServerSignature
}

// TODO not sure necessary
func NetEncodeMembers(x, y []kyber.Point) *NetMembers {
	return &NetMembers{
		X: x,
		Y: y,
	}
}

func (netmembers NetMembers) NetDecode() ([]kyber.Point, []kyber.Point) {
	return netmembers.X, netmembers.Y
}

func (context Context) NetEncode() *NetContext {
	G := NetEncodeMembers(context.Members())
	return &NetContext{
		G:      *G,
		H:      context.ClientsGenerators(),
		R:      context.ServersSecretsCommitments(),
		Roster: context.Roster,
	}
}

func (netcontext NetContext) NetDecode() (Context, error) {
	X, Y := netcontext.G.NetDecode()
	dagaContext, err := daga.NewAuthenticationContext(X, Y, netcontext.R, netcontext.H)
	if err != nil {
		return Context{}, err
	}
	roster := netcontext.Roster
	return Context{
		dagaContext,
		roster,
	}, nil
}

func NetEncodeClient(c daga.Client) *NetClient {
	return &NetClient{
		Index:      c.Index(),
		PrivateKey: c.PrivateKey(),
	}
}

func (c NetClient) NetDecode() (daga.Client, error) {
	return daga.NewClient(suite, c.Index, c.PrivateKey)
}

func NetEncodeClients(clients []daga.Client) ([]NetClient, error) {
	if len(clients) == 0 {
		return nil, errors.New("empty array")
	}
	var netClients []NetClient
	for _, client := range clients {
		netClient := NetEncodeClient(client)
		netClients = append(netClients, *netClient)
	}
	return netClients, nil
}

func NetDecodeClients(netClients []NetClient) ([]daga.Client, error) {
	if len(netClients) == 0 {
		return nil, errors.New("empty slice")
	}
	var clients []daga.Client
	for i, nc := range netClients {
		if c, err := nc.NetDecode(); err != nil {
			return nil, fmt.Errorf("Decode error at index %d\n%s", i, err)
		} else {
			clients = append(clients, c)
		}
	}
	return clients, nil
}

func NetEncodeServer(s daga.Server) *NetServer {
	return &NetServer{
		PrivateKey:     s.PrivateKey(),
		Index:          s.Index(),
		PerRoundSecret: s.RoundSecret(),
	}
}

func NetEncodeServers(servers []daga.Server) ([]NetServer, error) {
	if len(servers) == 0 {
		return nil, errors.New("empty array")
	}
	var netServers []NetServer
	for _, server := range servers {
		netServer := NetEncodeServer(server)
		netServers = append(netServers, *netServer)
	}
	return netServers, nil
}

func (s NetServer) NetDecode() (daga.Server, error) {
	server, err := daga.NewServer(suite, s.Index, s.PrivateKey)
	if err != nil {
		return nil, err
	}
	server.SetRoundSecret(s.PerRoundSecret)
	return server, nil
}

func NetEncodeAuthenticationMessage(context Context, msg *daga.AuthenticationMessage) *NetAuthenticationMessage {
	netContext := context.NetEncode()
	return &NetAuthenticationMessage{
		Context:  *netContext, // i.e. discard context part of message and use the one provided (FIXME seems I was tired)
		T0:       msg.T0,
		SCommits: msg.SCommits,
		Proof:    msg.P0,
	}
}

func (netmsg *NetAuthenticationMessage) NetDecode() (*daga.AuthenticationMessage, Context, error) {
	context, err := netmsg.Context.NetDecode()
	if err != nil {
		return nil, Context{}, fmt.Errorf("failed to decode context: %s", err)
	}
	msg := daga.AuthenticationMessage{
		C:  context.AuthenticationContext,
		P0: netmsg.Proof,
	}
	msg.SCommits = netmsg.SCommits
	msg.T0 = netmsg.T0
	return &msg, context, nil
}

func NetEncodeServerMessage(context Context, msg *daga.ServerMessage) *NetServerMessage {
	request := NetEncodeAuthenticationMessage(context, &msg.Request)
	return &NetServerMessage{
		Request: *request,
		Sigs:    msg.Sigs,
		Proofs:  msg.Proofs,
		Tags:    msg.Tags,
		Indexes: msg.Indexes,
	}
}

func (netmsg *NetServerMessage) NetDecode() (*daga.ServerMessage, Context, error) {
	request, context, err := netmsg.Request.NetDecode()
	if err != nil {
		return nil, Context{}, fmt.Errorf("failed to decode request: %s", err)
	}
	return &daga.ServerMessage{
		Request: *request,
		Tags:    netmsg.Tags,
		Proofs:  netmsg.Proofs,
		Sigs:    netmsg.Sigs,
		Indexes: netmsg.Indexes,
	}, context, nil
}
