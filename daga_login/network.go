package daga_login

import (
	"errors"
	"fmt"
	"github.com/dedis/kyber"
	"github.com/dedis/student_18_daga/sign/daga"
)

// TODO QUESTION ask, dumb IMO but feel kind of bad exporting things that are intended to be immutable so the in between solution is to have a separate struct
// TODO ~messy IMO, how to do it in a idiomatic and educated way ?

/*NetMembers provides a net compatible representation of the Members struct*/
type NetMembers struct {
	X []kyber.Point
	Y []kyber.Point
}
//
/*NetContext provides a net compatible representation of the daga.AuthenticationContext struct (which has non-exported fields)*/
type NetContext struct {
	G NetMembers
	R []kyber.Point
	H []kyber.Point
}

// to represent a daga.Client (which is currently an interface (maybe not that clever...) => hence the new struct)
type NetClient struct {
	PrivateKey kyber.Scalar
	Index int
}

// to represent a daga.Server (which is currently an interface (maybe not that clever...) => hence the new struct)
type NetServer struct {
	PrivateKey kyber.Scalar
	Index int
	PerRoundSecret kyber.Scalar
}

///*NetServerSignature provides a net compatible representation of the ServerSignature struct*/
//type NetServerSignature struct {
//	daga.ServerSignature  // for now nothing to do
//}
//
///*NetCommitment provides a net compatible representation of the Commitment struct*/
//type NetCommitment struct {
//	Commit NetPoint
//	Sig    NetServerSignature
//}
//
///*NetChallengeCheck provides a net compatible representation of the daga.ChallengeCheck struct*/
//type NetChallengeCheck struct {
//	Cs       NetScalar
//	Sigs     []NetServerSignature
//	Commits  []NetCommitment
//	Openings []NetScalar
//}
//
///*NetChallenge provides a net compatible representation of the daga.Challenge struct*/
//type NetChallenge struct {
//	Cs   NetScalar
//	Sigs []NetServerSignature
//}
//
///*NetClientProof provides a net compatible representation of the ClientProof struct*/
//type NetClientProof struct {
//	Cs NetScalar
//	T  []NetPoint
//	C  []NetScalar
//	R  []NetScalar
//}
//

/*NetAuthenticationMessage provides a net compatible representation of the daga.AuthenticationMessage struct (which embeds a context which has non-exported fields)*/
type NetAuthenticationMessage struct {
	Context NetContext
	SCommits  []kyber.Point
	T0      kyber.Point
	Proof   daga.ClientProof
}

/*NetServerMessage provides a net compatible representation of the daga.ServerMessage struct (which embeds an auth message struct which embeds a context which ..)*/
type NetServerMessage struct {
	Request NetAuthenticationMessage
	Tags    []kyber.Point
	Proofs  []daga.ServerProof
	Indexes []int
	Sigs    []daga.ServerSignature
}

func NetEncodeMembers(x, y []kyber.Point) *NetMembers {
	return &NetMembers{
		X:x,
		Y:y,
	}
}

func (netmembers NetMembers) NetDecode() ([]kyber.Point, []kyber.Point) {
	return netmembers.X, netmembers.Y
}

// QUESTION before doing anything useless ask all my marshalling questions to Linus
func NetEncodeContext(context *daga.AuthenticationContext) *NetContext {
	G := NetEncodeMembers(context.Members())
	return &NetContext{
		G:*G,
		H:context.ClientsGenerators(),
		R:context.ServersSecretsCommitments(),
	}
}

func (netcontext *NetContext) NetDecode() (*daga.AuthenticationContext, error) {
	X, Y := netcontext.G.NetDecode()
	return daga.NewAuthenticationContext(X, Y, netcontext.R, netcontext.H)
}

func NetEncodeClient(c daga.Client) *NetClient {
	return &NetClient{
		Index: c.Index(),
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
		PrivateKey: s.PrivateKey(),
		Index: s.Index(),
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

//func NetEncodeCommitment(com *daga.Commitment) (*NetCommitment, error) {
//	netcom := NetCommitment{Sig: *NetEncodeServerSignature(&com.ServerSignature)}
//
//	commit, err := NetEncodePoint(com.Commit)
//	if err != nil {
//		return nil, fmt.Errorf("Encode error in commit\n%s", err)
//	}
//	netcom.Commit = *commit
//
//	return &netcom, nil
//}
//
//func (netcom *NetCommitment) NetDecode(suite daga.Suite) (*daga.Commitment, error) {
//
//	commit, err := netcom.Commit.NetDecode(suite)
//	if err != nil {
//		return nil, fmt.Errorf("Decode error in commit\n%s", err)
//	}
//	sig := netcom.Sig.netDecode()
//
//	com := daga.Commitment{
//		Commit:commit,
//		ServerSignature: sig,
//	}
//
//	return &com, nil
//}
//
//func NetEncodeChallengeCheck(chall *daga.ChallengeCheck) (*NetChallengeCheck, error) {
//	netchall := NetChallengeCheck{}
//
//	for _, sig := range chall.Sigs {
//		netsig := NetEncodeServerSignature(&sig)
//		netchall.Sigs = append(netchall.Sigs, *netsig)
//	}
//
//	for i, com := range chall.Commits {
//		temp, err := NetEncodeCommitment(&com)
//		if err != nil {
//			return nil, fmt.Errorf("Encode error for commit %d\n%s", i, err)
//		}
//		netchall.Commits = append(netchall.Commits, *temp)
//	}
//
//	cs, err := NetEncodeScalar(chall.Cs)
//	if err != nil {
//		return nil, fmt.Errorf("Encode error for cs\n%s", err)
//	}
//	netchall.Cs = *cs
//
//	openings, err := NetEncodeScalars(chall.Openings)
//	if err != nil {
//		return nil, fmt.Errorf("Encode error in openings\n%s", err)
//	}
//	netchall.Openings = openings
//
//	return &netchall, nil
//}
//
//func (netchall *NetChallengeCheck) NetDecode(suite daga.Suite) (*daga.ChallengeCheck, error) {
//	chall := daga.ChallengeCheck{}
//
//	for _, sig := range netchall.Sigs {
//		chall.Sigs = append(chall.Sigs, sig.netDecode())
//	}
//
//	for i, com := range netchall.Commits {
//		temp, err := com.NetDecode(suite)
//		if err != nil {
//			return nil, fmt.Errorf("Decode error for commit %d\n%s", i, err)
//		}
//		chall.Commits = append(chall.Commits, *temp)
//	}
//
//	cs, err := netchall.Cs.NetDecode(suite)
//	if err != nil {
//		return nil, fmt.Errorf("Decode error for cs\n%s", err)
//	}
//	chall.Cs = cs
//
//	openings, err := NetDecodeScalars(suite, netchall.Openings)
//	if err != nil {
//		return nil, fmt.Errorf("Encode error in openings\n%s", err)
//	}
//	chall.Openings = openings
//
//	return &chall, nil
//}
//
//
//func NetEncodeChallenge(c daga.Challenge) (*NetChallenge, error) {
//	netchall := NetChallenge{}
//	for _, sig := range c.Sigs {
//		netchall.Sigs = append(netchall.Sigs, *NetEncodeServerSignature(&sig))
//	}
//
//	ncs, err := NetEncodeScalar(c.Cs)
//	if err != nil {
//		return nil, fmt.Errorf("Encode error for cs\n%s", err)
//	}
//	netchall.Cs = *ncs
//
//	return &netchall, nil
//}
//
//func (netchall *NetChallenge) NetDecode(suite daga.Suite) (*daga.Challenge, error) {
//	chall := daga.Challenge{}
//	for _, sig := range netchall.Sigs {
//		chall.Sigs = append(chall.Sigs, sig.netDecode())
//	}
//
//	cs, err := netchall.Cs.NetDecode(suite)
//	if err != nil {
//		return nil, fmt.Errorf("Decode error for cs\n%s", err)
//	}
//	chall.Cs = cs
//	return &chall, nil
//}
//

func NetEncodeAuthenticationMessage(msg *daga.AuthenticationMessage) *NetAuthenticationMessage {
	netContext := NetEncodeContext(&msg.C)
	return &NetAuthenticationMessage{
		Context: *netContext,
		T0:msg.T0,
		SCommits:msg.SCommits,
		Proof: msg.P0,
	}
}

func (netmsg *NetAuthenticationMessage) NetDecode(suite daga.Suite) (*daga.AuthenticationMessage, error) {
	context, err := netmsg.Context.NetDecode()
	if err != nil {
		return nil, fmt.Errorf("Decode error for context\n%s", err)
	}
	msg := daga.AuthenticationMessage{
		C:*context,
		P0:netmsg.Proof,
	}
	msg.SCommits = netmsg.SCommits
	msg.T0 = netmsg.T0
	return &msg, nil
}

func NetEncodeServerMessage(suite daga.Suite, msg *daga.ServerMessage)  *NetServerMessage {
	request := NetEncodeAuthenticationMessage(&msg.Request)
	return &NetServerMessage{
		Request:*request,
		Sigs:msg.Sigs,
		Proofs:msg.Proofs,
		Tags:msg.Tags,
		Indexes: msg.Indexes,
	}
}

func (netmsg *NetServerMessage) NetDecode(suite daga.Suite) (*daga.ServerMessage, error) {
	request, err := netmsg.Request.NetDecode(suite)
	if err != nil {
		return nil, fmt.Errorf("Decode error in request\n%s", err)
	}
	return &daga.ServerMessage{
		Request:*request,
		Tags:netmsg.Tags,
		Proofs:netmsg.Proofs,
		Sigs:netmsg.Sigs,
		Indexes:netmsg.Indexes,
	}, nil
}