package daga

import (
	"crypto/cipher"
	"crypto/sha256"
	"github.com/dedis/fixbuf"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/group/edwards25519"
	"github.com/dedis/kyber/util/random"
	"github.com/dedis/kyber/xof/blake2xb"
	"hash"
	"io"
	"reflect"
)

// SuiteEC is the EC crypto concrete implementation of the DAGA Suite interface,
// it is used to implement DAGA on the twisted Edwards curve that is birationally equivalent to Curve25519
// (i.e. the suite uses the same curve that is used in Ed25519's EdDSA signature scheme)
// TODO there are naming issues related to the curves in Kyber => create discussion (+ IMHO lacks guidelines and documentation too)
type suiteEC struct {
	edwards25519.Curve
}

// Returns a new Suite backed by a suiteEC TODO "singleton object" ?
func NewSuiteEC() Suite {
	return new(suiteEC)
}

// returns new hash.Hash computing the SHA-256 checksum
// this hash is used in DAGA to derive valid Scalars of the group used
func (s suiteEC) Hash() hash.Hash {
	// QUESTION should we care about length extension attacks on sha256 (we don't use it to build MAC's then...) ?
	// TODO maybe instead use sha512/256 ? (which should be faster on 64 bit architectures)
	return sha256.New()
}

// returns new hash.Hash computing the SHA-256 checksum
// this hash is used in DAGA as a random oracle to build the NIZK proof of the servers.
func (s suiteEC) hashTwo() hash.Hash {
	// needs to distribute "uniformly" (RO) the input to the range of valid exponents, (i.e. phi(p) for the shnorr group example)
	// => all field elements
	// QUESTION: but I'll have to admit that, since we work in a subgroup of order q I don't get why it was especially
	//  required a different range, in my mind it is sufficient to map to Zq, or put differently the exponents are eq mod q...(not formally written hope you understand what I mean)
	return s.Hash()
}

func (s suiteEC) RandomStream() cipher.Stream {
	return random.New()
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// used to give to the kyber.proof framework/package the methods it needs to operate, satisfy both proof.Suite and daga.Suite
type SuiteProof struct {
	Suite
}

func newSuiteProof(suite Suite) SuiteProof {
	return SuiteProof{suite}
}

// XOF returns an XOF which is implemented via the Blake2b hash.
func (s SuiteProof) XOF(key []byte) kyber.XOF {
	return blake2xb.New(key)
}

func (s SuiteProof) Write(w io.Writer, objs ...interface{}) error {
	return fixbuf.Write(w, objs)
}

func (s SuiteProof) Read(r io.Reader, objs ...interface{}) error {
	return fixbuf.Read(r, s, objs...)
}

// New implements the kyber.Encoding interface, needed to satisfy the kyber.Proof.Suite interface
func (s SuiteProof) New(t reflect.Type) interface{} {
	// QUESTION not totally sure if this is working, but a quick go playground hints it is ok.. https://play.golang.org/p/pkcd2RzlZad
	// TODO this implementation might be better that the one used in group/internal/marshalling/marshal.go
	//  and to my current understanding completely equivalent.
	//  (+) no need to have those package vars only to get their reflect type
	scalarInterface := reflect.TypeOf((*kyber.Scalar)(nil)).Elem()
	pointInterface := reflect.TypeOf((*kyber.Point)(nil)).Elem()
	if t.Implements(scalarInterface) {
		return s.Scalar()
	} else if t.Implements(pointInterface) {
		return s.Point()
	}
	return nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// TODO concrete implementation that uses same primitives that in DAGA paper (work in a schnorr group)
// TODO QUESTION did someone already implemented a kyber Schnorr group somewhere (with mod.Int) ? => no, might be a good idea
//type suiteSchnorr struct {
//	mod.Int
//}
//// Returns a new Suite backed by a SuiteSchnorr
//func NewSuiteEC() Suite {
//	return new(suiteSchnorr)
//}