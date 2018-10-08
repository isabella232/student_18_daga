package daga

import (
	"fmt"
	"github.com/dedis/kyber"
	"strconv"
)

//GenerateProofResponses creates the responses to the challenge cs sent by the servers
func (client *Client) GenerateProofResponses(context *authenticationContext, s kyber.Scalar, challenge *Challenge, v, w []kyber.Scalar) (c, r []kyber.Scalar, err error) {
	//Check challenge signatures
	msg, e := challenge.cs.MarshalBinary()
	if e != nil {
		return nil, nil, fmt.Errorf("Error in challenge conversion: %s", e)
	}
	for _, sig := range challenge.sigs {
		e = ECDSAVerify(context.g.y[sig.index], msg, sig.sig)
		if e != nil {
			return nil, nil, fmt.Errorf("%s", e)
		}
	}

	//Generates the c array
	for _, temp := range w {
		c = append(c, temp)
	}
	sum := suite.Scalar().Zero()
	for _, i := range w {
		sum = suite.Scalar().Add(sum, i)
	}
	c[client.index] = suite.Scalar().Sub(challenge.cs, sum)

	//Generates the responses
	for _, temp := range v {
		r = append(r, temp)
	}
	a := suite.Scalar().Mul(c[client.index], client.key.Private)
	r[2*client.index] = suite.Scalar().Sub(v[2*client.index], a)

	b := suite.Scalar().Mul(c[client.index], s)
	r[2*client.index+1] = suite.Scalar().Sub(v[2*client.index+1], b)

	return c, r, nil
}

//GetFinalLinkageTag checks the server's signatures and proofs
//It outputs the final linkage tag of the client
func (client *Client) GetFinalLinkageTag(context *authenticationContext, msg *ServerMessage) (Tf kyber.Point, err error) {
	//Input checks
	if context == nil || msg == nil {
		return nil, fmt.Errorf("Invalid inputs")
	}

	data, e := msg.request.ToBytes()
	if e != nil {
		return nil, fmt.Errorf("Error in request: %s", e)
	}
	for i := range msg.proofs {
		//Signature check
		temp, err := msg.tags[i].MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("Error in tags: %s", err)
		}
		data = append(data, temp...)

		temp, err = msg.proofs[i].ToBytes()
		if err != nil {
			return nil, fmt.Errorf("Error in proofs: %s", err)
		}
		data = append(data, temp...)

		data = append(data, []byte(strconv.Itoa(msg.indexes[i]))...)

		err = ECDSAVerify(context.g.y[msg.sigs[i].index], data, msg.sigs[i].sig)
		if err != nil {
			return nil, fmt.Errorf("Error in signature: "+strconv.Itoa(i)+"\n%s", err)
		}

		var valid bool
		p := msg.proofs[i]
		if p.r2 == nil {
			valid = verifyMisbehavingProof(context, i, &p, msg.request.sCommits[0])
		} else {
			valid = verifyServerProof(context, i, msg)
		}
		if !valid {
			return nil, fmt.Errorf("Invalid server proof")
		}
	}

	return msg.tags[len(msg.tags)-1], nil
}

/*ValidateClientMessage is an utility function to validate that a client message is correclty formed*/
// FIXME return error instead of bool
func ValidateClientMessage(msg *authenticationMessage) bool {
	//Number of clients
	i := len(msg.c.g.x)
	//Number of servers
	j := len(msg.c.g.y)
	//A commitment for each server exists and the second element is the generator S=(Z,g,S1,..,Sj)
	if len(msg.sCommits) != j+2 {
		// TODO log something
		return false
	}
	if !msg.sCommits[1].Equal(suite.Point().Mul(suite.Scalar().One(), nil)) {
		// TODO log something
		return false
	}
	//T0 not empty
	if msg.t0 == nil {
		// TODO log something
		return false
	}
	//Proof fields have the correct size
	if len(msg.p0.c) != i || len(msg.p0.r) != 2*i || len(msg.p0.t) != 3*i || msg.p0.cs == nil {
		// TODO log something
		return false
	}
	return true
}

/*ToBytes is a helper function used to convert a ClientMessage into []byte to be used in signatures*/
func (msg *authenticationMessage) ToBytes() (data []byte, err error) {
	data, e := msg.c.ToBytes()
	if e != nil {
		return nil, fmt.Errorf("Error in context: %s", e)
	}

	temp, e := PointArrayToBytes(&msg.sCommits)
	if e != nil {
		return nil, fmt.Errorf("Error in S: %s", e)
	}
	data = append(data, temp...)

	temp, e = msg.t0.MarshalBinary()
	if e != nil {
		return nil, fmt.Errorf("Error in T0: %s", e)
	}
	data = append(data, temp...)

	temp, e = msg.p0.ToBytes()
	if e != nil {
		return nil, fmt.Errorf("Error in proof: %s", e)
	}
	data = append(data, temp...)

	return data, nil
}

/*ToBytes is a helper function used to convert a ClientProof into []byte to be used in signatures*/
func (proof *clientProof) ToBytes() (data []byte, err error) {
	data, e := proof.cs.MarshalBinary()
	if e != nil {
		return nil, fmt.Errorf("Error in cs: %s", e)
	}

	temp, e := PointArrayToBytes(&proof.t)
	if e != nil {
		return nil, fmt.Errorf("Error in t: %s", e)
	}
	data = append(data, temp...)

	temp, e = ScalarArrayToBytes(&proof.c)
	if e != nil {
		return nil, fmt.Errorf("Error in c: %s", e)
	}
	data = append(data, temp...)

	temp, e = ScalarArrayToBytes(&proof.r)
	if e != nil {
		return nil, fmt.Errorf("Error in r: %s", e)
	}
	data = append(data, temp...)

	return data, nil
}
