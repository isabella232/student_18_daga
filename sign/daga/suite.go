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

type SuiteEC struct {
	edwards25519.Curve  // twisted edwards curve used in Ed25519 (birationnaly equivalent to Curve25519 <== FIXME naming issue in kyber, the Curve25519 of kyber is the same as edwards25519 only allowing vartime ops
}

func newSuiteEC() Suite {
	// QUESTION TODO ask if it is useful + return T or *T in interface var , what are the best practises and pitfalls to avoid ??
	return new(SuiteEC)
}

func (s SuiteEC) newKey() kyber.Scalar {
	return s.Curve.NewKey(s.RandomStream())
}

/* returns new hash.Hash computing the SHA-256 checksum
	this hash is used in DAGA to derive valid Scalars of the group used
	// TODO doc
 */
func (s SuiteEC) Hash() hash.Hash {
	return sha256.New()
}

func (s SuiteEC) hashTwo() hash.Hash {
	// FIXME
	return nil
}

func (s SuiteEC) RandomStream() cipher.Stream {
	return random.New()
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// QUESTION as an alternative to current construction SuiteProof, can just embedd edward's suite in SuiteEC and avoid code duplication that defines everything but I'm not fan of take everything even if not needed... ?
// QUESTION I think my solution is more flexible too but maybe overkill, the last and best alternative is to clean other packages to decouple the functionality that they internally need from the functionality that they need but that is dictated by the user code
// QUESTION ok I have no choice in fact, marshalling is internal to group.... why ?? => ok possible but now there is a little code duplication (New())
// used to give to the proof framework the method it needs, satisfy both proof.Suite and daga.Suite
type SuiteProof struct {
	Suite
}

func newSuiteProof(suite Suite) SuiteProof {
	return SuiteProof{suite}
}

func (s SuiteProof) Hash() hash.Hash {
	return s.Hash()
}

// XOF returns an XOF which is implemented via the Blake2b hash.
func (s SuiteProof) XOF(key []byte) kyber.XOF {
	return blake2xb.New(key)
}

func (s SuiteProof) Write(w io.Writer, objs ...interface{}) error {
	// TODO choose
	return fixbuf.Write(w, objs)
}

func (s SuiteProof) Read(r io.Reader, objs ...interface{}) error {
	// TODO choose
	return fixbuf.Read(r, s, objs...)
}

// New implements the kyber.Encoding interface
func (s SuiteProof) New(t reflect.Type) interface{} {
	// QUESTION FIXME not sure this is working, but a quick go playground hints it is ok.. https://play.golang.org/p/pkcd2RzlZad
	// TODO if this is ok, this implementation might be better that the one used in group/internal/marshalling/marshal.go
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
// TODO if time, concrete implementation that uses same primitives that in DAGA paper (work in a schnorr group)
//type SuiteSchnorr struct {
//	mod.Int
//}
//
//func newSuiteSchnorr() Suite {
//	return new(SuiteSchnorr)
//}

