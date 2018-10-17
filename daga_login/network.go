package daga_login

import (
	"fmt"
	"github.com/dedis/kyber"
	"github.com/dedis/student_18_daga/sign/daga"
)

// ......

//Provides functions to help with JSON marshal/unmarshal
// TODO see if all these things are useful (aren't there builtins facilities in go/onet/cothority ?) and well written when building the protocols and services

// QUESTION TODO IF still useful, see if I need to create wrapper structs to be able to add methods instead of defining functions (+ is this useful...bof)

/*NetPoint provides a JSON compatible representation of a kyber.Point*/
type NetPoint struct {
	Value []byte
}

/*NetScalar provides a JSON compatible representation of a kyber.Scalar*/
type NetScalar struct {
	Value []byte
}

/*NetMembers provides a JSON compatible representation of the Members struct*/
type NetMembers struct {
	X []NetPoint
	Y []NetPoint
}

/*NetContextEd25519 provides a JSON compatible representation of the ContextEd25519 struct*/
type NetContextEd25519 struct {
	G NetMembers
	R []NetPoint
	H []NetPoint
}

/*NetServerSignature provides a JSON compatible representation of the ServerSignature struct*/
type NetServerSignature struct {
	Index int
	Sig   []byte
}

/*NetCommitment provides a JSON compatible representation of the Commitment struct*/
type NetCommitment struct {
	Commit NetPoint
	Sig    NetServerSignature
}

/*NetChallengeCheck provides a JSON compatible representation of the daga.ChallengeCheck struct*/
type NetChallengeCheck struct {
	Cs       NetScalar
	Sigs     []NetServerSignature
	Commits  []NetCommitment
	Openings []NetScalar
}

/*NetChallenge provides a JSON compatible representation of the daga.Challenge struct*/
type NetChallenge struct {
	Cs   NetScalar
	Sigs []NetServerSignature
}

/*NetClientProof provides a JSON compatible representation of the ClientProof struct*/
type NetClientProof struct {
	Cs NetScalar
	T  []NetPoint
	C  []NetScalar
	R  []NetScalar
}

/*NetClientMessage provides a JSON compatible representation of the authenticationMessage struct*/
type NetClientMessage struct {
	Context NetContextEd25519
	SArray  []NetPoint
	T0      NetPoint
	Proof   NetClientProof
}

/*NetServerProof provides a JSON compatible representation of the ServerProof struct*/
type NetServerProof struct {
	T1 NetPoint
	T2 NetPoint
	T3 NetPoint
	C  NetScalar
	R1 NetScalar
	R2 NetScalar
}

/*NetServerMessage provides a JSON compatible representation of the daga.ServerMessage struct*/
type NetServerMessage struct {
	Request NetClientMessage
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
		temp, err := p.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("Encode error at index %d\n%s", i, err)
		}
		netpoints = append(netpoints, NetPoint{Value: temp})
	}
	return netpoints, nil
}

func NetDecodePoints(suite daga.Suite, netpoints []NetPoint) ([]kyber.Point, error) {
	var points []kyber.Point
	if len(netpoints) == 0 {
		return nil, fmt.Errorf("Empty array")
	}
	for i, p := range netpoints {
		temp := suite.Point().Null()
		err := temp.UnmarshalBinary(p.Value)
		if err != nil {
			return nil, fmt.Errorf("Decode error at index %d\n%s", i, err)
		}
		points = append(points, temp)
	}
	return points, nil
}

func NetEncodeScalars(scalars []kyber.Scalar) ([]NetScalar, error) {
	var netscalars []NetScalar
	for i, s := range scalars {
		temp, err := s.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("Encode error at index %d\n%s", i, err)
		}
		netscalars = append(netscalars, NetScalar{Value: temp})
	}
	return netscalars, nil
}

func NetDecodeScalars(suite daga.Suite, netscalars []NetScalar) ([]kyber.Scalar, error) {
	var scalars []kyber.Scalar
	if len(netscalars) == 0 {
		return nil, fmt.Errorf("Empty array")
	}
	for i, s := range netscalars {
		temp := suite.Scalar().Zero()
		err := temp.UnmarshalBinary(s.Value)
		if err != nil {
			return nil, fmt.Errorf("Decode error at index %d\n%s", i, err)
		}
		scalars = append(scalars, temp)
	}
	return scalars, nil
}

func NetEncode(x, y []kyber.Point) (*NetMembers, error) {
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

func NetDecode(suite daga.Suite, netmembers NetMembers) ([]kyber.Point, []kyber.Point, error) {
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
func ContextNetEncode(context *daga.AuthenticationContext) (*NetContextEd25519, error) {
	netcontext := NetContextEd25519{}

	G, err := NetEncode(context.g.x, context.g.y)
	if err != nil {
		return nil, fmt.Errorf("Encode error for members\n%s", err)
	}
	netcontext.G = *G

	R, err := NetEncodePoints(context.r)
	if err != nil {
		return nil, fmt.Errorf("Encode error in R\n%s", err)
	}
	netcontext.R = R

	H, err := NetEncodePoints(context.h)
	if err != nil {
		return nil, fmt.Errorf("Encode error in H\n%s", err)
	}
	netcontext.H = H

	return &netcontext, nil
}

func (netcontext *NetContextEd25519) NetDecode(suite daga.Suite) (*daga.AuthenticationContext, error) {
	context := daga.AuthenticationContext{}

	X, Y, err := NetDecode(suite, netcontext.G)
	if err != nil {
		return nil, fmt.Errorf("Decode error for members\n%s", err)
	}
	context.g.x = X
	context.g.y = Y

	R, err := NetDecodePoints(suite, netcontext.R)
	if err != nil {
		return nil, fmt.Errorf("Decode error in R\n%s", err)
	}
	context.r = R

	H, err := NetDecodePoints(suite, netcontext.H)
	if err != nil {
		return nil, fmt.Errorf("Decode error in H\n%s", err)
	}
	context.h = H

	return &context, nil
}

//netEncode for ServerSignature copies the data into a NetServerSignature structure
//No error can be returned
func ServerSignatureNetEncode(sig *daga.ServerSignature) NetServerSignature {
	return NetServerSignature{Sig: sig.sig, Index: sig.index}
}

//netDecode for NetServerSignature copies the data into a ServerSignature structure
//No error can be returned
func (netsig *NetServerSignature) netDecode() daga.ServerSignature {
	return daga.ServerSignature{sig: netsig.Sig, index: netsig.Index}
}

func CommitmentNetEncode(com *daga.Commitment) (*NetCommitment, error) {
	netcom := NetCommitment{Sig: ServerSignatureNetEncode(&com.ServerSignature)}

	commit, err := NetEncodePoint(com.commit)
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
		commit:commit,
		ServerSignature: sig,
	}

	return &com, nil
}

func ChallengeCheckNetEncode(chall *daga.ChallengeCheck) (*NetChallengeCheck, error) {
	netchall := NetChallengeCheck{}

	for _, sig := range chall.sigs {
		netchall.Sigs = append(netchall.Sigs, sig.netEncode())
	}

	for i, com := range chall.commits {
		temp, err := CommitmentNetEncode(com)
		if err != nil {
			return nil, fmt.Errorf("Encode error for commit %d\n%s", i, err)
		}
		netchall.Commits = append(netchall.Commits, *temp)
	}

	cs, err := NetEncodeScalar(chall.cs)
	if err != nil {
		return nil, fmt.Errorf("Encode error for cs\n%s", err)
	}
	netchall.Cs = *cs

	openings, err := NetEncodeScalars(chall.openings)
	if err != nil {
		return nil, fmt.Errorf("Encode error in openings\n%s", err)
	}
	netchall.Openings = openings

	return &netchall, nil
}

func (netchall *NetChallengeCheck) NetDecode(suite daga.Suite) (*daga.ChallengeCheck, error) {
	chall := daga.ChallengeCheck{}

	for _, sig := range netchall.Sigs {
		chall.sigs = append(chall.sigs, sig.netDecode())
	}

	for i, com := range netchall.Commits {
		temp, err := com.NetDecode(suite)
		if err != nil {
			return nil, fmt.Errorf("Decode error for commit %d\n%s", i, err)
		}
		chall.commits = append(chall.commits, *temp)
	}

	cs, err := netchall.Cs.NetDecode(suite)
	if err != nil {
		return nil, fmt.Errorf("Decode error for cs\n%s", err)
	}
	chall.cs = cs

	openings, err := NetDecodeScalars(suite, netchall.Openings)
	if err != nil {
		return nil, fmt.Errorf("Encode error in openings\n%s", err)
	}
	chall.openings = openings

	return &chall, nil
}

func ChallengeNetEncode(c daga.Challenge) (*NetChallenge, error) {
	netchall := NetChallenge{}
	for _, sig := range c.sigs {
		netchall.Sigs = append(netchall.Sigs, ServerSignatureNetEncode(sig))
	}

	cs, err := NetEncodeScalar(c.cs)
	if err != nil {
		return nil, fmt.Errorf("Encode error for cs\n%s", err)
	}
	netchall.Cs = *cs

	return &netchall, nil
}

func (netchall *NetChallenge) NetDecode(suite daga.Suite) (*daga.Challenge, error) {
	chall := daga.Challenge{}
	for _, sig := range netchall.Sigs {
		chall.sigs = append(chall.sigs, sig.netDecode())
	}

	cs, err := netchall.Cs.NetDecode(suite)
	if err != nil {
		return nil, fmt.Errorf("Decode error for cs\n%s", err)
	}
	chall.cs = cs

	return &chall, nil
}

func ClientProofNetEncode(proof *daga.ClientProof) (*NetClientProof, error) {
	netproof := NetClientProof{}
	cs, err := NetEncodeScalar(proof.cs)
	if err != nil {
		return nil, fmt.Errorf("Encode error for cs\n%s", err)
	}
	netproof.Cs = *cs

	T, err := NetEncodePoints(proof.t)
	if err != nil {
		return nil, fmt.Errorf("Encode error for t\n%s", err)
	}
	netproof.T = T

	C, err := NetEncodeScalars(proof.c)
	if err != nil {
		return nil, fmt.Errorf("Encode error for c\n%s", err)
	}
	netproof.C = C

	R, err := NetEncodeScalars(proof.r)
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
	proof.cs = cs

	t, err := NetDecodePoints(suite, netproof.T)
	if err != nil {
		return nil, fmt.Errorf("Decode error for t\n%s", err)
	}
	proof.t = t

	c, err := NetDecodeScalars(suite, netproof.C)
	if err != nil {
		return nil, fmt.Errorf("Decode error for c\n%s", err)
	}
	proof.c = c

	r, err := NetDecodeScalars(suite, netproof.R)
	if err != nil {
		return nil, fmt.Errorf("Decode error for r\n%s", err)
	}
	proof.r = r

	return &proof, nil
}

func AuthenticationMessageNetEncode(msg *daga.AuthenticationMessage) (*NetClientMessage, error) {
	netmsg := NetClientMessage{}

	context, err := ContextNetEncode(msg.c)
	if err != nil {
		return nil, fmt.Errorf("Encode error for context\n%s", err)
	}
	netmsg.Context = *context

	s, err := NetEncodePoints(msg.sCommits)
	if err != nil {
		return nil, fmt.Errorf("Encode errof for sArray\n%s", err)
	}
	netmsg.SArray = s

	t0, err := NetEncodePoint(msg.t0)
	if err != nil {
		return nil, fmt.Errorf("Encode error in t0\n%s", err)
	}
	netmsg.T0 = *t0

	proof, err := ClientProofNetEncode(msg.p0)
	if err != nil {
		return nil, fmt.Errorf("Encode error in proof\n%s", err)
	}
	netmsg.Proof = *proof

	return &netmsg, nil
}

func (netmsg *NetClientMessage) NetDecode(suite daga.Suite) (*daga.AuthenticationMessage, error) {
	msg := daga.AuthenticationMessage{}

	context, err := netmsg.Context.NetDecode(suite)
	if err != nil {
		return nil, fmt.Errorf("Decode error for context\n%s", err)
	}
	msg.c = *context

	s, err := NetDecodePoints(suite, netmsg.SArray)
	if err != nil {
		return nil, fmt.Errorf("Decode errof for sArray\n%s", err)
	}
	msg.sCommits = s

	t0, err := netmsg.T0.NetDecode(suite)
	if err != nil {
		return nil, fmt.Errorf("Decode error in t0\n%s", err)
	}
	msg.t0 = t0

	proof, err := netmsg.Proof.NetDecode(suite)
	if err != nil {
		return nil, fmt.Errorf("Decode error in proof\n%s", err)
	}
	msg.p0 = *proof

	return &msg, nil
}

func ServerProofNetEncode(suite daga.Suite, proof *daga.ServerProof) (*NetServerProof, error) {
	netproof := NetServerProof{}
	t1, err := NetEncodePoint(proof.t1)
	if err != nil {
		return nil, fmt.Errorf("Encode error in t1\n%s", err)
	}
	netproof.T1 = *t1

	t2, err := NetEncodePoint(proof.t2)
	if err != nil {
		return nil, fmt.Errorf("Encode error in t2\n%s", err)
	}
	netproof.T2 = *t2

	t3, err := NetEncodePoint(proof.t3)
	if err != nil {
		return nil, fmt.Errorf("Encode error in t3\n%s", err)
	}
	netproof.T3 = *t3

	c, err := NetEncodeScalar(proof.c)
	if err != nil {
		return nil, fmt.Errorf("Encode error for c\n%s", err)
	}
	netproof.C = *c

	r1, err := NetEncodeScalar(proof.r1)
	if err != nil {
		return nil, fmt.Errorf("Encode error for r1\n%s", err)
	}
	netproof.R1 = *r1

	r2, err := NetEncodeScalar(proof.r2)
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
	proof.t1 = t1

	t2, err := netproof.T2.NetDecode(suite)
	if err != nil {
		return nil, fmt.Errorf("Decode error in t2\n%s", err)
	}
	proof.t2 = t2

	t3, err := netproof.T3.NetDecode(suite)
	if err != nil {
		return nil, fmt.Errorf("Decode error in t3\n%s", err)
	}
	proof.t3 = t3

	c, err := netproof.C.NetDecode(suite)
	if err != nil {
		return nil, fmt.Errorf("Decode error in c\n%s", err)
	}
	proof.c = c

	r1, err := netproof.R1.NetDecode(suite)
	if err != nil {
		return nil, fmt.Errorf("Decode error in r1\n%s", err)
	}
	proof.r1 = r1

	r2, err := netproof.R2.NetDecode(suite)
	if err != nil {
		return nil, fmt.Errorf("Decode error in r2\n%s", err)
	}
	proof.r2 = r2

	return &proof, nil
}

func ServerMessageNetEncode(suite daga.Suite, msg *daga.ServerMessage)  (*NetServerMessage, error) {
	netmsg := NetServerMessage{Indexes: msg.indexes}

	request, err := AuthenticationMessageNetEncode(msg.request)
	if err != nil {
		return nil, fmt.Errorf("Encode error in request\n%s", err)
	}
	netmsg.Request = *request

	tags, err := NetEncodePoints(msg.tags)
	if err != nil {
		return nil, fmt.Errorf("Encode error in tags\n%s", err)
	}
	netmsg.Tags = tags

	for i, p := range msg.proofs {
		temp, err := ServerProofNetEncode(suite, p)
		if err != nil {
			return nil, fmt.Errorf("Encode error in proof at index %d\n%s", i, err)
		}
		netmsg.Proofs = append(netmsg.Proofs, *temp)
	}

	for _, s := range msg.sigs {
		temp := ServerSignatureNetEncode(s)
		netmsg.Sigs = append(netmsg.Sigs, temp)
	}

	return &netmsg, nil
}

func (netmsg *NetServerMessage) NetDecode(suite daga.Suite) (*daga.ServerMessage, error) {
	msg := daga.ServerMessage{indexes: netmsg.Indexes}

	request, err := netmsg.Request.NetDecode(suite)
	if err != nil {
		return nil, fmt.Errorf("Decode error in request\n%s", err)
	}
	msg.request = *request

	tags, err := NetDecodePoints(suite, netmsg.Tags)
	if err != nil {
		return nil, fmt.Errorf("Decode error in tags\n%s", err)
	}
	msg.tags = tags

	for i, p := range netmsg.Proofs {
		temp, err := p.NetDecode(suite)
		if err != nil {
			return nil, fmt.Errorf("Decode error in proof at index %d\n%s", i, err)
		}
		msg.proofs = append(msg.proofs, *temp)
	}

	for _, s := range netmsg.Sigs {
		temp := s.netDecode()
		msg.sigs = append(msg.sigs, temp)
	}

	return &msg, nil
}