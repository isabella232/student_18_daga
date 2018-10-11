package daga

import (
	"errors"
	"fmt"
	"github.com/dedis/kyber"
	"strconv"
)

// GetFinalLinkageTag checks the server's signatures and proofs
// and outputs the final linkage tag of the client or an error
// FIXME WTF client receiver .. ? => see if makes sense when building the protocol and services
// FIXME QUESTION not sure that the verifyserverproof belongs inside this method in the client..DAGA paper specify that it is the servers that check it
// TODO but guess this won't do any harm, will need to decide when building the service
func (c Client) getFinalLinkageTag(context *authenticationContext, msg *ServerMessage) (Tf kyber.Point, err error) {
	//Input checks
	if context == nil || msg == nil || len(msg.tags) == 0 {
		return nil, errors.New("invalid inputs")
	}

	data, e := msg.request.ToBytes()
	if e != nil {
		return nil, fmt.Errorf("error in request: %s", e)
	}
	for i := range msg.proofs {
		//Signature check
		temp, err := msg.tags[i].MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("error in tags: %s", err)
		}
		data = append(data, temp...)

		temp, err = msg.proofs[i].ToBytes()
		if err != nil {
			return nil, fmt.Errorf("error in proofs: %s", err)
		}
		data = append(data, temp...)

		data = append(data, []byte(strconv.Itoa(msg.indexes[i]))...)

		err = SchnorrVerify(context.g.y[msg.sigs[i].index], data, msg.sigs[i].sig)
		if err != nil {
			return nil, fmt.Errorf("error in signature: %d\n%s", i, err)
		}

		var valid bool
		p := msg.proofs[i]
		if p.r2 == nil {
			valid = verifyMisbehavingProof(context, i, &p, msg.request.sCommits[0])
		} else {
			valid = verifyServerProof(context, i, msg)
		}
		if !valid {
			return nil, fmt.Errorf("invalid server proof")
		}
	}

	return msg.tags[len(msg.tags)-1], nil
}

// ValidateClientMessage is an utility function to validate that a client message is correclty formed
// FIXME return error instead of bool
func validateClientMessage(msg authenticationMessage) bool {
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
func (msg authenticationMessage) ToBytes() (data []byte, err error) {
	data, e := msg.c.ToBytes()
	if e != nil {
		return nil, fmt.Errorf("error in context: %s", e)
	}

	temp, e := PointArrayToBytes(msg.sCommits)
	if e != nil {
		return nil, fmt.Errorf("error in S: %s", e)
	}
	data = append(data, temp...)

	temp, e = msg.t0.MarshalBinary()
	if e != nil {
		return nil, fmt.Errorf("error in T0: %s", e)
	}
	data = append(data, temp...)

	temp, e = msg.p0.ToBytes()
	if e != nil {
		return nil, fmt.Errorf("error in proof: %s", e)
	}
	data = append(data, temp...)

	return data, nil
}

//ToBytes is a helper function used to convert a ClientProof into []byte to be used in signatures
func (proof clientProof) ToBytes() (data []byte, err error) {
	data, e := proof.cs.MarshalBinary()
	if e != nil {
		return nil, fmt.Errorf("error in cs: %s", e)
	}

	temp, e := PointArrayToBytes(proof.t)
	if e != nil {
		return nil, fmt.Errorf("error in t: %s", e)
	}
	data = append(data, temp...)

	temp, e = ScalarArrayToBytes(proof.c)
	if e != nil {
		return nil, fmt.Errorf("error in c: %s", e)
	}
	data = append(data, temp...)

	temp, e = ScalarArrayToBytes(proof.r)
	if e != nil {
		return nil, fmt.Errorf("error in r: %s", e)
	}
	data = append(data, temp...)

	return data, nil
}
