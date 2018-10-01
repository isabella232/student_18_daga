package daga

import (
	"fmt"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/group/edwards25519"
	"github.com/dedis/kyber/sign/schnorr"
)

// QUESTION this code is not copy pastable into kyber this makes no sense, (e.g no Suite, strange things, etc..)

/*Members contains the list of client's (X) and server's (Y) public keys*/
type Members struct {
	X []kyber.Point
	Y []kyber.Point
}

/*ContextEd25519 holds all the context elements for DAGA with the ed25519 curve
group is the curve
R is the server's commitments
H is the client's per-round generators*/
type ContextEd25519 struct {
	G Members
	R []kyber.Point
	H []kyber.Point
}

//Suite exports the cryptographic interface to external packages
var Suite = edwards25519.NewBlakeSHA256Ed25519()
var suite = edwards25519.NewBlakeSHA256Ed25519() // QUESTION WTF ?

/*ECDSASign gnerates a Schnorr signature*/
// QUESTION another WTF, why bring ECDSA here ? but ok ..
func ECDSASign(priv kyber.Scalar, msg []byte) (s []byte, err error) {
	//Input checks
	if priv == nil {
		return nil, fmt.Errorf("Empty private key")
	}
	if msg == nil || len(msg) == 0 {
		return nil, fmt.Errorf("Empty message")
	}

	s, err = schnorr.Sign(suite, priv, msg)
	if err != nil {
		return nil, fmt.Errorf("Error in the signature generation")
	}
	return s, nil
}

/*ECDSAVerify checks if a Schnorr signature is valid*/
// QUESTION same WTF as above
func ECDSAVerify(public kyber.Point, msg, sig []byte) (err error) {
	//Input checks
	if public == nil {
		return fmt.Errorf("Empty public key")
	}
	if msg == nil || len(msg) == 0 {
		return fmt.Errorf("Empty message")
	}
	if sig == nil || len(sig) == 0 {
		return fmt.Errorf("Empty signature")
	}

	err = schnorr.Verify(suite, public, msg, sig)
	return err
}

/*ToBytes is a utility functton to convert a ContextEd25519 into []byte, used in signatures*/
// QUESTION WTF ?
func (context *ContextEd25519) ToBytes() (data []byte, err error) {
	temp, e := PointArrayToBytes(&context.G.X)
	if e != nil {
		return nil, fmt.Errorf("Error in X: %s", e)
	}
	data = append(data, temp...)

	temp, e = PointArrayToBytes(&context.G.Y)
	if e != nil {
		return nil, fmt.Errorf("Error in Y: %s", e)
	}
	data = append(data, temp...)

	temp, e = PointArrayToBytes(&context.H)
	if e != nil {
		return nil, fmt.Errorf("Error in H: %s", e)
	}
	data = append(data, temp...)

	temp, e = PointArrayToBytes(&context.R)
	if e != nil {
		return nil, fmt.Errorf("Error in R: %s", e)
	}
	data = append(data, temp...)

	return data, nil
}

/*PointArrayToBytes is a utility function to convert a kyber.Point array into []byte, used in signatures*/
// QUESTION same as above
func PointArrayToBytes(array *[]kyber.Point) (data []byte, err error) {
	for _, p := range *array {
		temp, e := p.MarshalBinary()
		if e != nil {
			return nil, fmt.Errorf("Error in S: %s", e)
		}
		data = append(data, temp...)
	}
	return data, nil
}

/*ScalarArrayToBytes is a utility function to convert a kyber.Scalar array into []byte, used in signatures*/
func ScalarArrayToBytes(array *[]kyber.Scalar) (data []byte, err error) {
	for _, s := range *array {
		temp, e := s.MarshalBinary()
		if e != nil {
			return nil, fmt.Errorf("Error in S: %s", e)
		}
		data = append(data, temp...)
	}
	return data, nil
}
