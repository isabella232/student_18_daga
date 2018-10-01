package daga

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/proof"
	"github.com/dedis/onet/log"
	"strconv"
)

// cipherStreamReader adds a Read method onto a cipher.Stream,
// so that it can be used as an io.Reader.
// TODO FIXME QUESTION copy pasted from hashProve => need to put it elsewhere in kyber to allow reusability !!
type cipherStreamReader struct {
	cipher.Stream
}
func (s *cipherStreamReader) Read(in []byte) (int, error) {
	x := make([]byte, len(in))
	s.XORKeyStream(x, x)
	copy(in, x)
	return len(in), nil
}

// Sigma-protocol proof.ProverContext used to conduct interactive proofs with a verifier over the network
// TODO create specific clientprover, take inspiration and directions from hashprover and deniableprover
// UESTION should I instead try to see if I can reuse proof.deniableProver ? and override needed methods ?
// UESTION what about the deniable prover thing in package and protocols and clique ? should I use them or build my own things ?
// UESTION can I use deniable prover and instantiate a custom verifier as a proxy for the actual remote verifier ?
// QUESTION => I'd say no, better to write my own and see later if it or parts can be made reusable or be shared with.. in proof.something
type clientProverCtx struct {
	SuiteProof
	messages chan kyber.Point  // to extract the prover's msgs from prover and make them accessible (i.e. fix the API...)
	challenges chan kyber.Scalar // to give challenges to the prover
}

// TODO doc + QUESTION convention for newSomething returning a pointer ?
func newClientProverCtx(suite Suite, n int) clientProverCtx {
	return clientProverCtx{
		SuiteProof: newSuiteProof(suite),
		messages: make(chan kyber.Point, n),
		challenges: make(chan kyber.Scalar),
	}
}

// "Send message to verifier" or make the prover's messages available to our/user code
// QUESTION TODO try to understand why message was designed to have type interface{}
func (cpCtx *clientProverCtx) Put(message interface{}) error {
	// QUESTION I kind of feel that I'm fixing an unusable framework and the resulting thing is a mess..
	// need documentation
	// DECISION : not really my job now => move forward keep things like they are => extend / override / copy deniable prover and basta
	// then only maybe add my stone
	if msg, ok := message.(kyber.Point); ok {
		cpCtx.messages <- msg
		log.Info("client proof, " + strconv.Itoa(len(cpCtx.messages)) + " prover's message/commit available in channel ..")
		return nil
	} else {
		return errors.New("clientProverCtx.Put: commit message from prover not of type kyber.Point (" + fmt.Sprint("%T", message) + ")")
	}
}

// Get public randomness / challenge from verifier/chan..
func (cpCtx *clientProverCtx) PubRand(message ...interface{}) error {
	challenge := <- cpCtx.challenges

	// QUESTION how can this be the way to go ?? why not a slice instead of variadic stuff
}

// Get private randomness
// TODO kind of copy pasted from hasprovercontext => see how/where to share code/helpers
func (cpCtx *clientProverCtx) PriRand(message ...interface{}) error {
	if err := cpCtx.Read(&cipherStreamReader{cpCtx.RandomStream()}, message...); err != nil {
		return fmt.Errorf("error reading random stream: %v", err.Error())
	}
	return nil
}

/*clientProof stores the client's proof P as of "Syta - Identity Management Through Privacy Preserving Aut 4.3.7"
 */
type clientProof struct {
	cs kyber.Scalar
	t  []kyber.Point
	c  []kyber.Scalar
	r  []kyber.Scalar
}

// FIXME doc + where to put it + why not make the daga functions methods attached to daga authcontext
func newClientProver(context authenticationContext, client client, tagAndCommitments initialTagAndCommitments) proof.Prover {
	// build the OR-predicate
	andPreds := make([]proof.Predicate, 0, len(context.g.x))
	choice := make(map[proof.Predicate]int, 1)  // QUESTION maybe give sizes to the make calls or not..
	sval := make(map[string]kyber.Scalar, 2)
	pval := make(map[string]kyber.Point, 1 + 4 * len(context.g.x))
	pval["G"] = suite.Point().Base()
	//	build all the internal And predicates (one for each client in current auth. group
	for i, pubKey := range context.g.x {
		// client AndPred
		iStr := strconv.Itoa(i)
		//		i) client i’s linkage tag T0 is created with respect to his per-round generator hi
		linkageTagValidPred := proof.Rep("T0" + iStr, "s" + iStr, "H" + iStr)
		// 		ii)  S is a proper commitment to the product of all secrets that i shares with the servers
		commitmentValidPred := proof.Rep("Sm" + iStr, "s" + iStr, "G")
		// 		iii) client i's private key xi corresponds to one of the public keys included in the group definition G
		knowOnePrivateKeyPred := proof.Rep("X" + iStr, "x" + iStr, "G")

		clientAndPred := proof.And(linkageTagValidPred, commitmentValidPred, knowOnePrivateKeyPred)

		andPreds = append(andPreds, clientAndPred)

		// build maps for both public and secret values needed to construct the Prover from the predicate
		pval["X" + iStr] = pubKey
		pval["H" + iStr] = context.h[i]
		if i == client.index {
			sval["s" + iStr] = tagAndCommitments.s
			sval["x" + iStr] = client.key.Private
			pval["T0" + iStr] = tagAndCommitments.t0
			pval["Sm" + iStr] = tagAndCommitments.sCommits[len(tagAndCommitments.sCommits)-1]
		} else {
			pval["T0" + iStr] = suite.Point().Pick(suite.RandomStream())
			pval["Sm" + iStr] = suite.Point().Pick(suite.RandomStream())
		}
	}
	finalOrPred := proof.Or(andPreds...)
	choice[finalOrPred] = client.index

	// retrieve sigma-protocol Prover from OR-predicate
	// QUESTION FIXME remove the "hack"/addition on suite, ask if possible to decouple the functions that are only needed internally by proof framework and the ones that come from user of framework
	// QUESTION FIXME to avoid bringing the dependencies of proof into "user" code
	prover := finalOrPred.Prover(newSuiteProof(suite), sval, pval, choice)
	return prover
}
