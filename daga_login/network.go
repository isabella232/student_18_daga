package daga_login
import (
	"errors"
	"fmt"
	"github.com/dedis/kyber"
	"github.com/dedis/student_18_daga/sign/daga"
)

// ......
// TODO see if all these things are useful (aren't there builtins facilities in go/onet/cothority ?) and well written when building the protocols and services

/*NetPoint provides a net compatible representation of a kyber.Point*/
type NetPoint struct {
	Value []byte
}

/*NetScalar provides a net compatible representation of a kyber.Scalar*/
type NetScalar struct {
	Value []byte
}

/*NetMembers provides a net compatible representation of the Members struct*/
type NetMembers struct {
	X []NetPoint
	Y []NetPoint
}

/*NetContextEd25519 provides a net compatible representation of the ContextEd25519 struct*/
type NetContextEd25519 struct {
	G NetMembers
	R []NetPoint
	H []NetPoint
}

// FIXME all these things are way to messy IMO, how to do it in a idiomatic and educated way ? I feel I'm doing 2 thesis at a time and the result will be a worthless mess
type NetClient struct {
	PrivateKey NetScalar
	Index int
}

type NetServer struct {
	PrivateKey NetScalar
	Index int
	PerRoundSecret NetScalar
}

/*NetServerSignature provides a net compatible representation of the ServerSignature struct*/
type NetServerSignature struct {
	daga.ServerSignature  // for now nothing to do
}

/*NetCommitment provides a net compatible representation of the Commitment struct*/
type NetCommitment struct {
	Commit NetPoint
	Sig    NetServerSignature
}

/*NetChallengeCheck provides a net compatible representation of the daga.ChallengeCheck struct*/
type NetChallengeCheck struct {
	Cs       NetScalar
	Sigs     []NetServerSignature
	Commits  []NetCommitment
	Openings []NetScalar
}

/*NetChallenge provides a net compatible representation of the daga.Challenge struct*/
type NetChallenge struct {
	Cs   NetScalar
	Sigs []NetServerSignature
}

/*NetClientProof provides a net compatible representation of the ClientProof struct*/
type NetClientProof struct {
	Cs NetScalar
	T  []NetPoint
	C  []NetScalar
	R  []NetScalar
}

/*NetAuthenticationMessage provides a net compatible representation of the authenticationMessage struct*/
type NetAuthenticationMessage struct {
	Context NetContextEd25519
	SArray  []NetPoint
	T0      NetPoint
	Proof   NetClientProof
}

/*NetServerProof provides a net compatible representation of the ServerProof struct*/
type NetServerProof struct {
	T1 NetPoint
	T2 NetPoint
	T3 NetPoint
	C  NetScalar
	R1 NetScalar
	R2 NetScalar
}

/*NetServerMessage provides a net compatible representation of the daga.ServerMessage struct*/
type NetServerMessage struct {
	Request NetAuthenticationMessage
	Tags    []NetPoint
	Proofs  []NetServerProof
	Indexes []int
	Sigs    []NetServerSignature
}

func NetEncodePoint(point kyber.Point) (*NetPoint, error) {
	value, err := point.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("Encode error\n%s", err)
	}

	return &NetPoint{Value: value}, nil
}

func (netpoint *NetPoint) NetDecode(suite daga.Suite) (kyber.Point, error) {
	point := suite.Point().Null()
	err := point.UnmarshalBinary(netpoint.Value)
	if err != nil {
		return nil, fmt.Errorf("Decode error\n%s", err)
	}

	return point, nil
}

func NetEncodeScalar(scalar kyber.Scalar) (*NetScalar, error) {
	value, err := scalar.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("Encode error\n%s", err)
	}

	return &NetScalar{Value: value}, nil
}

func (netscalar *NetScalar) NetDecode(suite daga.Suite) (kyber.Scalar, error) {
	scalar := suite.Scalar().Zero()
	err := scalar.UnmarshalBinary(netscalar.Value)
	if err != nil {
		return nil, fmt.Errorf("Decode error\n%s", err)
	}

	return scalar, nil
}

func NetEncodePoints(points []kyber.Point) ([]NetPoint, error) {
	var netpoints []NetPoint
	for i, p := range points {
		if netPoint, err := NetEncodePoint(p); err != nil {
			return nil, fmt.Errorf("Encode error at index %d\n%s", i, err)
		} else {
			netpoints = append(netpoints, *netPoint)
		}
	}
	return netpoints, nil
}

func NetDecodePoints(suite daga.Suite, netpoints []NetPoint) ([]kyber.Point, error) {
	if len(netpoints) == 0 {
		return nil, fmt.Errorf("Empty array")
	}
	var points []kyber.Point
	for i, p := range netpoints {
		if point, err := p.NetDecode(suite); err != nil {
			return nil, fmt.Errorf("Decode error at index %d\n%s", i, err)
		} else {
			points = append(points, point)
		}
	}
	return points, nil
}

func NetEncodeScalars(scalars []kyber.Scalar) ([]NetScalar, error) {
	var netscalars []NetScalar
	for i, s := range scalars {
		if netscalar, err := NetEncodeScalar(s); err != nil {
			return nil, fmt.Errorf("Encode error at index %d\n%s", i, err)
		} else {
			netscalars = append(netscalars, *netscalar)
		}
	}
	return netscalars, nil
}

func NetDecodeScalars(suite daga.Suite, netscalars []NetScalar) ([]kyber.Scalar, error) {
	if len(netscalars) == 0 {
		return nil, fmt.Errorf("Empty array")
	}
	var scalars []kyber.Scalar
	for i, s := range netscalars {
		if scalar, err := s.NetDecode(suite); err != nil {
			return nil, fmt.Errorf("Decode error at index %d\n%s", i, err)
		} else {
			scalars = append(scalars, scalar)
		}
	}
	return scalars, nil
}

func NetEncodeMembers(x, y []kyber.Point) (*NetMembers, error) {
	netmembers := NetMembers{}

	X, err := NetEncodePoints(x)
	if err != nil {
		return nil, fmt.Errorf("Encode error in X\n%s", err)
	}
	netmembers.X = X

	Y, err := NetEncodePoints(y)
	if err != nil {
		return nil, fmt.Errorf("Encode error in Y\n%s", err)
	}
	netmembers.Y = Y

	return &netmembers, nil
}

func (netmembers NetMembers) NetDecode(suite daga.Suite) ([]kyber.Point, []kyber.Point, error) {
	X, err := NetDecodePoints(suite, netmembers.X)
	if err != nil {
		return nil, nil, fmt.Errorf("Decode error in X\n%s", err)
	}

	Y, err := NetDecodePoints(suite, netmembers.Y)
	if err != nil {
		return nil, nil, fmt.Errorf("Decode error in Y\n%s", err)
	}

	return X, Y, nil
}

// QUESTION before doing anything useless ask all my marshalling questions to Linus
func NetEncodeContext(context *daga.AuthenticationContext) (*NetContextEd25519, error) {
	netcontext := NetContextEd25519{}

	G, err := NetEncodeMembers(context.Members())
	if err != nil {
		return nil, fmt.Errorf("Encode error for members\n%s", err)
	}
	netcontext.G = *G

	R, err := NetEncodePoints(context.ServersSecretsCommitments())
	if err != nil {
		return nil, fmt.Errorf("Encode error in R\n%s", err)
	}
	netcontext.R = R

	H, err := NetEncodePoints(context.ClientsGenerators())
	if err != nil {
		return nil, fmt.Errorf("Encode error in H\n%s", err)
	}
	netcontext.H = H

	return &netcontext, nil
}

func (netcontext *NetContextEd25519) NetDecode(suite daga.Suite) (*daga.AuthenticationContext, error) {

	X, Y, err := netcontext.G.NetDecode(suite)
	if err != nil {
		return nil, fmt.Errorf("Decode error for members\n%s", err)
	}

	R, err := NetDecodePoints(suite, netcontext.R)
	if err != nil {
		return nil, fmt.Errorf("Decode error in R\n%s", err)
	}

	H, err := NetDecodePoints(suite, netcontext.H)
	if err != nil {
		return nil, fmt.Errorf("Decode error in H\n%s", err)
	}

	return daga.NewAuthenticationContext(X, Y, R, H)
}

func NetEncodeClient(c daga.Client) (*NetClient, error) {
	netClient := NetClient{}
	if netPrivKey, err := NetEncodeScalar(c.PrivateKey()); err != nil {
		return nil, fmt.Errorf("encode error for privateKey: %s", err)
	} else {
		netClient.PrivateKey = *netPrivKey
	}
	netClient.Index = c.Index()
	return &netClient, nil
}

func (c NetClient) NetDecode() (daga.Client, error) {
	privateKey, err := c.PrivateKey.NetDecode(suite)
	if err != nil {
		return nil, fmt.Errorf("decode error for privateKey: %s", err)
	}
	return daga.NewClient(suite, c.Index, privateKey)
}

func NetEncodeClients(clients []daga.Client) ([]NetClient, error) {
	if len(clients) == 0 {
		return nil, errors.New("empty array")
	}
	var netClients []NetClient
	for _, client := range clients {
		if netClient, err := NetEncodeClient(client); err != nil {
			return nil, err
		} else {
			netClients = append(netClients, *netClient)
		}
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

func NetEncodeServer(c daga.Server) (*NetServer, error) {
	netServer := NetServer{}
	if netPrivKey, err := NetEncodeScalar(c.PrivateKey()); err != nil {
		return nil, fmt.Errorf("encode error for privateKey: %s", err)
	} else {
		netServer.PrivateKey = *netPrivKey
	}
	if netRoundSecret, err := NetEncodeScalar(c.RoundSecret()); err != nil {
		return nil, fmt.Errorf("encode error for round-secret: %s", err)
	} else {
		netServer.PerRoundSecret = *netRoundSecret
	}
	netServer.Index = c.Index()
	return &netServer, nil
}

func NetEncodeServers(servers []daga.Server) ([]NetServer, error) {
	if len(servers) == 0 {
		return nil, errors.New("empty array")
	}
	var netServers []NetServer
	for _, server := range servers {
		if netServer, err := NetEncodeServer(server); err != nil {
			return nil, err
		} else {
			netServers = append(netServers, *netServer)
		}
	}
	return netServers, nil
}

func NetEncodeServerSignature(sig *daga.ServerSignature) *NetServerSignature {
	return &NetServerSignature{*sig}
}

func (netsig *NetServerSignature) netDecode() daga.ServerSignature {
	return netsig.ServerSignature
}

func NetEncodeCommitment(com *daga.Commitment) (*NetCommitment, error) {
	netcom := NetCommitment{Sig: *NetEncodeServerSignature(&com.ServerSignature)}

	commit, err := NetEncodePoint(com.Commit)
	if err != nil {
		return nil, fmt.Errorf("Encode error in commit\n%s", err)
	}
	netcom.Commit = *commit

	return &netcom, nil
}

func (netcom *NetCommitment) NetDecode(suite daga.Suite) (*daga.Commitment, error) {

	commit, err := netcom.Commit.NetDecode(suite)
	if err != nil {
		return nil, fmt.Errorf("Decode error in commit\n%s", err)
	}
	sig := netcom.Sig.netDecode()

	com := daga.Commitment{
		Commit:commit,
		ServerSignature: sig,
	}

	return &com, nil
}

func NetEncodeChallengeCheck(chall *daga.ChallengeCheck) (*NetChallengeCheck, error) {
	netchall := NetChallengeCheck{}

	for _, sig := range chall.Sigs {
		netsig := NetEncodeServerSignature(&sig)
		netchall.Sigs = append(netchall.Sigs, *netsig)
	}

	for i, com := range chall.Commits {
		temp, err := NetEncodeCommitment(&com)
		if err != nil {
			return nil, fmt.Errorf("Encode error for commit %d\n%s", i, err)
		}
		netchall.Commits = append(netchall.Commits, *temp)
	}

	cs, err := NetEncodeScalar(chall.Cs)
	if err != nil {
		return nil, fmt.Errorf("Encode error for cs\n%s", err)
	}
	netchall.Cs = *cs

	openings, err := NetEncodeScalars(chall.Openings)
	if err != nil {
		return nil, fmt.Errorf("Encode error in openings\n%s", err)
	}
	netchall.Openings = openings

	return &netchall, nil
}

func (netchall *NetChallengeCheck) NetDecode(suite daga.Suite) (*daga.ChallengeCheck, error) {
	chall := daga.ChallengeCheck{}

	for _, sig := range netchall.Sigs {
		chall.Sigs = append(chall.Sigs, sig.netDecode())
	}

	for i, com := range netchall.Commits {
		temp, err := com.NetDecode(suite)
		if err != nil {
			return nil, fmt.Errorf("Decode error for commit %d\n%s", i, err)
		}
		chall.Commits = append(chall.Commits, *temp)
	}

	cs, err := netchall.Cs.NetDecode(suite)
	if err != nil {
		return nil, fmt.Errorf("Decode error for cs\n%s", err)
	}
	chall.Cs = cs

	openings, err := NetDecodeScalars(suite, netchall.Openings)
	if err != nil {
		return nil, fmt.Errorf("Encode error in openings\n%s", err)
	}
	chall.Openings = openings

	return &chall, nil
}


func NetEncodeChallenge(c daga.Challenge) (*NetChallenge, error) {
	netchall := NetChallenge{}
	for _, sig := range c.Sigs {
		netchall.Sigs = append(netchall.Sigs, *NetEncodeServerSignature(&sig))
	}

	ncs, err := NetEncodeScalar(c.Cs)
	if err != nil {
		return nil, fmt.Errorf("Encode error for cs\n%s", err)
	}
	netchall.Cs = *ncs

	return &netchall, nil
}

func (netchall *NetChallenge) NetDecode(suite daga.Suite) (*daga.Challenge, error) {
	chall := daga.Challenge{}
	for _, sig := range netchall.Sigs {
		chall.Sigs = append(chall.Sigs, sig.netDecode())
	}

	cs, err := netchall.Cs.NetDecode(suite)
	if err != nil {
		return nil, fmt.Errorf("Decode error for cs\n%s", err)
	}
	chall.Cs = cs
	return &chall, nil
}

func NetEncodeClientProof(proof *daga.ClientProof) (*NetClientProof, error) {
	netproof := NetClientProof{}
	cs, err := NetEncodeScalar(proof.Cs)
	if err != nil {
		return nil, fmt.Errorf("Encode error for cs\n%s", err)
	}
	netproof.Cs = *cs

	T, err := NetEncodePoints(proof.T)
	if err != nil {
		return nil, fmt.Errorf("Encode error for t\n%s", err)
	}
	netproof.T = T

	C, err := NetEncodeScalars(proof.C)
	if err != nil {
		return nil, fmt.Errorf("Encode error for c\n%s", err)
	}
	netproof.C = C

	R, err := NetEncodeScalars(proof.R)
	if err != nil {
		return nil, fmt.Errorf("Encode error for r\n%s", err)
	}
	netproof.R = R
	return &netproof, nil
}

func (netproof *NetClientProof) NetDecode(suite daga.Suite) (*daga.ClientProof, error) {
	proof := daga.ClientProof{}
	cs, err := netproof.Cs.NetDecode(suite)
	if err != nil {
		return nil, fmt.Errorf("Decode error for cs\n%s", err)
	}
	proof.Cs = cs

	t, err := NetDecodePoints(suite, netproof.T)
	if err != nil {
		return nil, fmt.Errorf("Decode error for t\n%s", err)
	}
	proof.T = t

	c, err := NetDecodeScalars(suite, netproof.C)
	if err != nil {
		return nil, fmt.Errorf("Decode error for c\n%s", err)
	}
	proof.C = c

	r, err := NetDecodeScalars(suite, netproof.R)
	if err != nil {
		return nil, fmt.Errorf("Decode error for r\n%s", err)
	}
	proof.R = r

	return &proof, nil
}

func NetEncodeAuthenticationMessage(msg *daga.AuthenticationMessage) (*NetAuthenticationMessage, error) {
	netmsg := NetAuthenticationMessage{}

	context := msg.C
	netcontext, err := NetEncodeContext(&context)
	if err != nil {
		return nil, fmt.Errorf("Encode error for context\n%s", err)
	}
	netmsg.Context = *netcontext

	s, err := NetEncodePoints(msg.SCommits)
	if err != nil {
		return nil, fmt.Errorf("Encode errof for sArray\n%s", err)
	}
	netmsg.SArray = s

	t0, err := NetEncodePoint(msg.T0)
	if err != nil {
		return nil, fmt.Errorf("Encode error in t0\n%s", err)
	}
	netmsg.T0 = *t0

	proof := msg.P0
	netproof, err := NetEncodeClientProof(&proof)
	if err != nil {
		return nil, fmt.Errorf("Encode error in proof\n%s", err)
	}
	netmsg.Proof = *netproof

	return &netmsg, nil
}

func (netmsg *NetAuthenticationMessage) NetDecode(suite daga.Suite) (*daga.AuthenticationMessage, error) {
	msg := daga.AuthenticationMessage{}

	context, err := netmsg.Context.NetDecode(suite)
	if err != nil {
		return nil, fmt.Errorf("Decode error for context\n%s", err)
	}
	msg.C = *context

	s, err := NetDecodePoints(suite, netmsg.SArray)
	if err != nil {
		return nil, fmt.Errorf("Decode errof for sArray\n%s", err)
	}
	msg.SCommits = s

	t0, err := netmsg.T0.NetDecode(suite)
	if err != nil {
		return nil, fmt.Errorf("Decode error in t0\n%s", err)
	}
	msg.T0 = t0

	proof, err := netmsg.Proof.NetDecode(suite)
	if err != nil {
		return nil, fmt.Errorf("Decode error in proof\n%s", err)
	}
	msg.P0 = *proof

	return &msg, nil
}

func NetEncodeServerProof(suite daga.Suite, proof *daga.ServerProof) (*NetServerProof, error) {
	netproof := NetServerProof{}
	t1, err := NetEncodePoint(proof.T1)
	if err != nil {
		return nil, fmt.Errorf("Encode error in t1\n%s", err)
	}
	netproof.T1 = *t1

	t2, err := NetEncodePoint(proof.T2)
	if err != nil {
		return nil, fmt.Errorf("Encode error in t2\n%s", err)
	}
	netproof.T2 = *t2

	t3, err := NetEncodePoint(proof.T3)
	if err != nil {
		return nil, fmt.Errorf("Encode error in t3\n%s", err)
	}
	netproof.T3 = *t3

	c, err := NetEncodeScalar(proof.C)
	if err != nil {
		return nil, fmt.Errorf("Encode error for c\n%s", err)
	}
	netproof.C = *c

	r1, err := NetEncodeScalar(proof.R1)
	if err != nil {
		return nil, fmt.Errorf("Encode error for r1\n%s", err)
	}
	netproof.R1 = *r1

	r2, err := NetEncodeScalar(proof.R2)
	if err != nil {
		return nil, fmt.Errorf("Encode error for r2\n%s", err)
	}
	netproof.R2 = *r2
	return &netproof, nil
}

func (netproof *NetServerProof) NetDecode(suite daga.Suite) (*daga.ServerProof, error) {
	proof := daga.ServerProof{}
	t1, err := netproof.T1.NetDecode(suite)
	if err != nil {
		return nil, fmt.Errorf("Decode error in t1\n%s", err)
	}
	proof.T1 = t1

	t2, err := netproof.T2.NetDecode(suite)
	if err != nil {
		return nil, fmt.Errorf("Decode error in t2\n%s", err)
	}
	proof.T2 = t2

	t3, err := netproof.T3.NetDecode(suite)
	if err != nil {
		return nil, fmt.Errorf("Decode error in t3\n%s", err)
	}
	proof.T3 = t3

	c, err := netproof.C.NetDecode(suite)
	if err != nil {
		return nil, fmt.Errorf("Decode error in c\n%s", err)
	}
	proof.C = c

	r1, err := netproof.R1.NetDecode(suite)
	if err != nil {
		return nil, fmt.Errorf("Decode error in r1\n%s", err)
	}
	proof.R1 = r1

	r2, err := netproof.R2.NetDecode(suite)
	if err != nil {
		return nil, fmt.Errorf("Decode error in r2\n%s", err)
	}
	proof.R2 = r2
	return &proof, nil
}

func NetEncodeServerMessage(suite daga.Suite, msg *daga.ServerMessage)  (*NetServerMessage, error) {
	netmsg := NetServerMessage{Indexes: msg.Indexes}

	request, err := NetEncodeAuthenticationMessage(&msg.Request)
	if err != nil {
		return nil, fmt.Errorf("Encode error in request\n%s", err)
	}
	netmsg.Request = *request

	tags, err := NetEncodePoints(msg.Tags)
	if err != nil {
		return nil, fmt.Errorf("Encode error in tags\n%s", err)
	}
	netmsg.Tags = tags

	for i, p := range msg.Proofs {
		temp, err := NetEncodeServerProof(suite, &p)
		if err != nil {
			return nil, fmt.Errorf("Encode error in proof at index %d\n%s", i, err)
		}
		netmsg.Proofs = append(netmsg.Proofs, *temp)
	}

	for _, s := range msg.Sigs {
		temp := NetEncodeServerSignature(&s)
		netmsg.Sigs = append(netmsg.Sigs, *temp)
	}

	return &netmsg, nil
}

func (netmsg *NetServerMessage) NetDecode(suite daga.Suite) (*daga.ServerMessage, error) {
	msg := daga.ServerMessage{Indexes: netmsg.Indexes}

	request, err := netmsg.Request.NetDecode(suite)
	if err != nil {
		return nil, fmt.Errorf("Decode error in request\n%s", err)
	}
	msg.Request = *request

	tags, err := NetDecodePoints(suite, netmsg.Tags)
	if err != nil {
		return nil, fmt.Errorf("Decode error in tags\n%s", err)
	}
	msg.Tags = tags

	for i, p := range netmsg.Proofs {
		temp, err := p.NetDecode(suite)
		if err != nil {
			return nil, fmt.Errorf("Decode error in proof at index %d\n%s", i, err)
		}
		msg.Proofs = append(msg.Proofs, *temp)
	}

	for _, s := range netmsg.Sigs {
		temp := s.netDecode()
		msg.Sigs = append(msg.Sigs, temp)
	}

	return &msg, nil
}
