package daga
// TODO organize those in a "sub package" of daga "clientProof" and rename everything with better names

import (
	"errors"
	"fmt"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/proof"
	"strconv"
)

// TODO verifier
// Sigma-protocol proof.VerifierContext used to conduct interactive proofs with a prover over the network
type clientVerifierCtx struct {
	SuiteProof
}

// TODO doc
// n = #clients in auth. group = #predicates in OrProof
func newClientVerifierCtx(suite Suite) *clientVerifierCtx {
	// FIXME: see if/where I need to deep copy passed DATA !!
	return &clientVerifierCtx{
		SuiteProof:        newSuiteProof(suite),
	}
}

// satisfy the proof.VerifierContext interface, TODO doc, not meant to be used by "user" code
func (cvCtx clientVerifierCtx) Get(message interface{}) error {

	return nil
}

// satisfy the proof.VerifierContext interface, TODO doc, not meant to be used by "user" code
func (cvCtx clientVerifierCtx) PubRand(message ...interface{}) error {
	return nil
}

// Sigma-protocol proof.ProverContext used to conduct interactive proofs with a verifier over the network
// TODO see if can make an interface from my API wrapper to put in kyber.proof
// TODO doc, plus don't use the channels directly there are methods for that
type clientProverCtx struct {
	SuiteProof
	commitsChan       chan kyber.Point    // to extract the prover's commitments from Prover (via Put) and make them accessible (i.e. kind of fix the API...)
	challengeChan     chan kyber.Scalar   // to give master challenge to the Prover (via PubRand) and make them accessible (i.e. kind of fix the API...)
	subChallengesChan chan []kyber.Scalar // to extract the prover's sub-challenges from Prover (via Put) and make them accessible (i.e. kind of fix the API...)
	responsesChan     chan kyber.Scalar   // to extract the prover's responses from Prover (via Put) and make them accessible (i.e. kind of fix the API...)
}

// TODO doc
// n = #clients in auth. group = #predicates in OrProof
func newClientProverCtx(suite Suite, n int) *clientProverCtx {
	// FIXME: see if/where I need to deep copy passed DATA !!
	return &clientProverCtx{
		SuiteProof:        newSuiteProof(suite),
		commitsChan:       make(chan kyber.Point, 3*n),  // Point FIFO of size n. Prover - Put() -> commitsChan -> commitments() - user-code
		challengeChan:     make(chan kyber.Scalar),    // Scalar unbuffered chan. user-code - receiveChallenge() -> challengeChan -> Prover - PubRand()
		subChallengesChan: make(chan []kyber.Scalar),  // []Scalar unbuffered chan. Prover - Put() -> subChallengesChan -> user-code - receiveChallenge()
		responsesChan:     make(chan kyber.Scalar, 2*n), // Scalar FIFO of size n. Prover - Put() -> responsesChan -> user-code - responses()
	}
}

// make the Prover's messages available to our/user code
// satisfy the proof.ProverContext interface, TODO doc, not meant to be used by "user" code see commitments, receiveChallenges and responses methods
// QUESTION is there a way/pattern to implement interface with public methods while making them private...? guess no but..
func (cpCtx clientProverCtx) Put(message interface{}) error {
	switch msg := message.(type) {
	case kyber.Point:
		// received message is a commitment
		// send commitment to user code (via commits channel via commitments method)
		cpCtx.commitsChan <- msg // blocks if chan full which should never happen (buffer should have the right size (#clients/predicates in the OrPred))
		return nil
	case []kyber.Scalar:
		// received message is a slice of all n sub-challenges
		// send sub-challenges to user code (via subChallenges channel via receiveChallenge method)
		cpCtx.subChallengesChan <- msg // blocks until user code received them (sync: "recv happens before send completes")
		return nil
	case kyber.Scalar:
		// received message is a response
		// send response to user code (via responses channel via responses method)
		cpCtx.responsesChan <- msg // block if chan full which should never happen (buffer should have the right size, #clients/predicates in the OrPred)
		return nil
	default:
		return errors.New("clientProverCtx.Put: message from prover not of type kyber.Point neither kyber.Scalar nor []kyber.Scalar (" + fmt.Sprintf("%T", message) + ")")
	}
}

// retrieve the Prover's first message/commitments t=(t1.0, t1.10, t1.11,..., tn.0, tn.10, tn.11 )
func (cpCtx clientProverCtx) commitments() ([]kyber.Point, error) {
	commitments := make([]kyber.Point, 0, cap(cpCtx.commitsChan))
	for commit := range cpCtx.commitsChan {
		// get commitment from Prover (via commitsChan channel via Put method)
		commitments = append(commitments, commit)
	} // blocks if chan empty (should not be a problem), (and until chan closed by sending side when done (in PubRand()))
	// TODO maybe add a watchdog that will return/log an error if blocked too long  ? (because this should never happen !)
	// TODO in fact good idea but not here, add a test case

	if len(commitments) != cap(commitments) {
		return nil, errors.New("clientProverCtx.commitments: received wrong number of commitments (" +
			strconv.Itoa(len(commitments)) + ") expected " + strconv.Itoa(cap(commitments)))
	}
	return commitments, nil
}

// retrieve the Prover's responses r=(r1.0, r1.1,..., rn.0, rn.1)
func (cpCtx clientProverCtx) responses() ([]kyber.Scalar, error) {
	responses := make([]kyber.Scalar, 0, cap(cpCtx.responsesChan))
	for response := range cpCtx.responsesChan {
		// get response from Prover (via responsesChan channel via Put method)
		responses = append(responses, response)
	} // blocks if chan empty (should not be a problem), (and until chan closed by sending side when done (when Prover.prove done))
	// TODO maybe add a watchdog that will return an error if blocked too long  ? (because this should never happen !)
	// TODO in fact good idea but not here, add a test case

	if len(responses) != cap(responses) {
		return nil, errors.New("clientProverCtx.responses: received wrong number of responses (" +
			strconv.Itoa(len(responses)) + ") expected " + strconv.Itoa(cap(responses)))
	}
	return responses, nil
}

// Get public randomness / master challenge from verifier/chan
// TODO doc, not meant to be used by "user" code see receiveChallenge method
func (cpCtx clientProverCtx) PubRand(message ...interface{}) error {
	if len(message) != 1 {
		// TODO see if useful to keep this check
		return errors.New("clientProverCtx.PubRand called with less or more than one arg, this is not expected")
	}
	// close commitsChan, Prover is done sending the commits with Put => release sync barrier with commitments() method
	close(cpCtx.commitsChan)

	// get challenge from remote verifier (via challenge channel via receiveChallenge method)
	// blocks until challenge received from remote verifier and sent in channel by user code (via receiveChallenge method)
	challenge := <-cpCtx.challengeChan

	switch scalar := message[0].(type) {
	case kyber.Scalar:
		scalar.Set(challenge)
		return nil
	default:
		return errors.New("clientProverCtx.PubRand called with type " + fmt.Sprintf("%T", message[0]) + " instead of kyber.Scalar")
	}
}

// send master challenge to Prover
// TODO doc
func (cpCtx clientProverCtx) receiveChallenges(challenge kyber.Scalar) []kyber.Scalar {
	// send master challenge to Prover (via challenge channel via PubRand method) => release sync barrier with PubRand()
	cpCtx.challengeChan <- challenge // blocks until Prover received the master challenge (sync: "recv happens before send completes")

	// receive sub-challenges
	subChallenges := <-cpCtx.subChallengesChan
	return subChallenges
}

// Get private randomness
// TODO kind of copy pasted from hasprovercontext => see how/where to share code/helpers
// TODO doc, not meant to be used by "user" code
func (cpCtx clientProverCtx) PriRand(message ...interface{}) error {
	if len(message) > 0 {
		switch scalar := message[0].(type) {
		case kyber.Scalar:
			scalar.Pick(cpCtx.RandomStream())
		default:
			return errors.New("clientProverCtx.PriRand called with type " + fmt.Sprintf("%T", message[0]) + " instead of kyber.Scalar")
		}
	}
	return errors.New("clientProverCtx.PriRand called with no arg, this is not expected")
}

// TODO FIXME maybe, pack the 2 channels in a new type and add methods NewTestProxy NewProxy etc..
// for now only add two channels to the newClientProof function
//type serverProxy struct {
//	send
//}

/*clientProof stores the client's proof P as of "Syta - Identity Management Through Privacy Preserving Aut 4.3.7"
 */
type clientProof struct {
	cs kyber.Scalar
	t  []kyber.Point
	c  []kyber.Scalar
	r  []kyber.Scalar
}

// FIXME names and interface
// TODO decide communication with server
// TODO lambdas/callerpassedclosures higherorder functions whatever to call to communicate with remote server
// TODO doc, build the clientProof (as of DAGA paper) and return it to caller
func newClientProof(context authenticationContext,
					client Client,
					tagAndCommitments initialTagAndCommitments,
					s kyber.Scalar,
					pushCommitments chan<- []kyber.Point,
					pullChallenge <-chan kyber.Scalar) (clientProof, error) {
	//construct the proof.Prover for client's PK and its proof.ProverContext
	prover := newClientProver(context, client, tagAndCommitments, s)
	proverCtx := newClientProverCtx(suite, len(context.g.x))

	//3-move interaction with server
	//	start the proof.Prover and proof machinery in new goroutine
	var P clientProof
	// TODO create named function/method
	go func() {
		defer close(proverCtx.responsesChan)
		if err := prover(proverCtx); err != nil {
			// TODO onet.log something
		}
	}()

	//	get initial commitments from Prover
	if commits, err := proverCtx.commitments(); err != nil {
		return clientProof{}, err
	} else {
		P.t = commits
	}

	//	forward them to random remote server/verifier (over *anon.* circuit etc.. concern of the caller code !!)
	pushCommitments <- P.t

	//	receive master challenge from remote server (over *anon.* circuit etc.. concern of the caller code !!)
	challenge := <- pullChallenge
	// FIXME new Challenge struct in chan to add signature and then check signature
	P.cs = challenge

	//	forward master challenge to Prover in order to continue the proof process, and receive the sub-challenges from Prover
	P.c = proverCtx.receiveChallenges(P.cs)

	//	get final responses from Prover
	if responses, err := proverCtx.responses(); err != nil {
		return clientProof{}, err
	} else {
		P.r = responses
	}

	// forward them to remote server
	// TODO or not I think in fact, the responses are part of the clientProof part of authmessage M0 <- this one sent
	return P, nil
}

// TODO doc
func newClientProofAndPred(k int) (clientAndPred proof.Predicate) {
	// client AndPred
	kStr := strconv.Itoa(k)
	//		i) client i’s linkage tag T0 is created with respect to his per-round generator hi
	linkageTagValidPred := proof.Rep("T0"+kStr, "s"+kStr, "H"+kStr)
	// 		ii)  S is a proper commitment to the product of all secrets that i shares with the servers
	commitmentValidPred := proof.Rep("Sm"+kStr, "s"+kStr, "G")
	// 		iii) client i's private key xi corresponds to one of the public keys included in the group definition G
	knowOnePrivateKeyPred := proof.Rep("X"+kStr, "x"+kStr, "G")

	clientAndPred = proof.And(linkageTagValidPred, commitmentValidPred, knowOnePrivateKeyPred)
	return
}

// TODO doc, + see if can clean/lift a little the parameters + QUESTION move where I'll put server related functions and structs since it will be the servers that will use it or ?
func newClientVerifier(context authenticationContext) proof.Verifier {
	// build the OR-predicate
	andPreds := make([]proof.Predicate, 0, len(context.g.x))
	for k, _ := range context.g.x {
		andPreds = append(andPreds, newClientProofAndPred(k))
	}
	finalOrPred := proof.Or(andPreds...)
	return finalOrPred.Verifier(newSuiteProof(suite), )
}

// TODO doc, + see if can clean/lift a little the parameters + better name for s parameter throughout all methods
// FIXME small dilemna, here, as I first wrote I can build the prover (and naturally the predicate) in one pass
// TODO but as I need to build the predicate only (not the additional maps etcc.) in order to build the Verifier
// TODO I have 2 choices 1) keep same implementation => duplicate some code to build the predicate when constructing a verifier
// TODO 				 2) have a new function create the predicate only and reuse it in both newClientProver and newClientVerifier
// TODO						(means I need 2 loop to build the Prover...)
// TODO 	for now I chose the code duplication since there is not much code to begin with.. and it is ~trivial
func newClientProver(context authenticationContext, client Client, tagAndCommitments initialTagAndCommitments, s kyber.Scalar) proof.Prover {
	// build the OR-predicate
	andPreds := make([]proof.Predicate, 0, len(context.g.x))
	choice := make(map[proof.Predicate]int, 1) // QUESTION maybe give sizes to the make calls or not..
	sval := make(map[string]kyber.Scalar, 2)
	pval := make(map[string]kyber.Point, 1+4*len(context.g.x))
	pval["G"] = suite.Point().Base()
	//	build all the internal And predicates (one for each client in current auth. group
	for k, pubKey := range context.g.x {
		kStr := strconv.Itoa(k)
		andPreds = append(andPreds, newClientProofAndPred(k))

		// build maps for both public and secret values needed to construct the Prover from the predicate
		pval["X"+kStr] = pubKey
		pval["H"+kStr] = context.h[k]
		if k == client.index {
			sval["s"+kStr] = s
			sval["x"+kStr] = client.key.Private
			pval["T0"+kStr] = tagAndCommitments.t0
			pval["Sm"+kStr] = tagAndCommitments.sCommits[len(tagAndCommitments.sCommits)-1]
		} else {
			// FIXME QUESTION how to properly simulate the other predicates ? other student set those always to the same and current user T0 and Sm
			// I don't see why not set them to random points so for now I keep my interpretation
			// Ok maybe I see, we need a convention with the verifier on what is being proven i.e. the predicate if we draw those point randomly
			// we cannot expect the verifier to pick the same ones => either need way to give this additional information to verifier
			// or always keep same point ! => keep same point + I kind of feel I was wrong an we NEED to keep same point
			pval["T0"+kStr] = suite.Point().Pick(suite.RandomStream())
			pval["Sm"+kStr] = suite.Point().Pick(suite.RandomStream())
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
