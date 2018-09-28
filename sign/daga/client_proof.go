package daga

import (
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/proof"
	"strconv"
)

// Sigma-protocol proof.ProverContext used to conduct interactive proofs with a verifier over the network
// QUESTION FIXME name
// QUESTION should I instead try to see if I can reuse proof.deniableProver ?
// QUESTION what about the deniable prover thing in package and protocols and clique ? should I use them or build my own things ?
// QUESTION can I use deniable prover and instantiate the a custom verifier as a proxy for the actual remote verifier ?

type dagaProver struct {
	SuiteProof
	t
}

func (dp *dagaProver) Put(message interface{}) error {
	// Add onto accumulated prover message
	return dp.Write(dp.msg, message)
}


/*clientProof stores the client's proof P as of "Syta - Identity Management Through Privacy Preserving Aut 4.3.7"
 */
type clientProof struct {
	cs kyber.Scalar
	t  []kyber.Point
	c  []kyber.Scalar
	r  []kyber.Scalar
}

// TODO create specific clientprover, take inspiration and directions from hashprover and deniableprover

// FIXME Name + doc
func newClientProver() proof.Prover {
	// build the OR-predicate
	// TODO make DAGA function !
	andPreds := make([]proof.Predicate, 0, len(context.g.x))
	choice := make(map[proof.Predicate]int, 1) // QUESTION maybe give sizes to the make calls or not..
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
		if i == c.index {
			sval["s" + iStr] = ts.s
			sval["x" + iStr] = c.key.Private
			pval["T0" + iStr] = ts.t0
			pval["Sm" + iStr] = ts.sCommits[len(ts.sCommits)-1]
		} else {
			pval["T0" + iStr] = suite.Point().Pick(suite.RandomStream())
			pval["Sm" + iStr] = suite.Point().Pick(suite.RandomStream())
		}
	}
	finalOrPred := proof.Or(andPreds...)
	choice[finalOrPred] = c.index

	// retrieve sigma-protocol Prover from OR-predicate and build ProverContext.
	// QUESTION FIXME remove the "hack"/addition on suite, ask if possible to decouple the functions that are only needed internally by proof framework and the ones that come from user of framework
	// FIXME to avoid bringing the dependencies of proof into "user" code
	prover := finalOrPred.Prover(newSuiteProof(suite), sval, pval, choice)
	// QUESTION how to correctly build the provercontext and use the prover ?
		var proverCtx proof.ProverContext

	prover(proverCtx)


}
