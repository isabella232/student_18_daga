package daga

import (
	"crypto/cipher"
	"fmt"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/proof"
	"github.com/dedis/onet/log"
	"strconv"
)

// Sigma-protocol proof.ProverContext used to conduct interactive proofs with a verifier over the network
// TODO create specific clientprover, take inspiration and directions from hashprover and deniableprover
// QUESTION should I instead try to see if I can reuse proof.deniableProver ? and override needed methods ?
// QUESTION what about the deniable prover thing in package and protocols and clique ? should I use them or build my own things ?
// QUESTION can I use deniable prover and instantiate a custom verifier as a proxy for the actual remote verifier ?

// QUESTION => I'd say no, better to write my own and see later if it or parts can be made reusable or be shared with.. in proof.something
type clientProverCtx struct {
	SuiteProof
	//prirand io.Reader  // TODO not convinced it is useful.. but for harmony with other implementations ...or maybe not in fact
}

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

// Send message to verifier
func (cpCtx clientProverCtx) Put(message interface{}) error {
	// TODO get server from context (=> TODO choose random server at context creation)
	// TODO send the message => TODO see whats available in onet/cothority
	// TODO OR grab the message and put it in a channel toward user code that will do the work elsewhere, probably better !
	// TODO but it is not possible currently since prf.prove() call put then call pubrand
	// TODO yes it is possible but unnecessarily complicated IMHO and looks like it was done in deniable prover
	// TODO I find this is bad design, the prove and hence Prover() fucntions should not do what they are doing now
	// TODO maybe better to do things in CPS style or async await
	// TODO e.g add aditional arg into Put() to register what the function should do/call once it has finished
	// QUESTION I kind of feel that I'm fixing an unusable framework and that the resulting thing is a mess..
	// DECISION : not really my job now => move forward keep things like they are => extend / override deniable prover and basta
	log.Info("client proof, sending message to ..")
	return nil
}

// Get public randomness / challenge from verifier
func (cpCtx clientProverCtx) PubRand(message ...interface{}) error {
	// TODO listen for message/challenge from verifier
	// TODO deserialize it and put it in message
	// QUESTION what is the suite.read suite.write about in deniable prover context ? to serialize deserialize it ? => yes use it !
	return nil
}

// Get private randomness
// TODO kind of copy pasted from hasprovercontext => see how/where to share code/helpers
func (cpCtx clientProverCtx) PriRand(message ...interface{}) error {
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
