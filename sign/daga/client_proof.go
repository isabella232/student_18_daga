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

// TODO FIXME if resulting code not good implements proof from scratch without using proof framework

// Sigma-protocol proof.ProverContext used to conduct interactive proofs with a verifier over the network
// UESTION what about the deniable prover thing in package and protocols and clique ? should I use them or build my own things ?
// UESTION should I instead try to see if I can reuse proof.deniableProver ? and override needed methods ?
// UESTION should I use deniable prover and instantiate a custom verifier as a proxy for the actual remote verifier ?
// UESTION I kind of feel that I'm fixing an "unusable" framework and the resulting thing is a mess..
// at the very least the framework need more documentation
// DECISION : not really my job now => move forward keep things like they are => extend / override / copy deniable prover and basta
// then only maybe add my stone and/or, see later if it or parts can be made reusable or be shared with.. in proof.something
// e.g. if framework modified or extended to use channels like this "simple wrapper"
// TODO doc, plus don't use the channels directly there are methods for that
type clientProverCtx struct {
	SuiteProof
	commitsChan chan kyber.Point  	 // to extract the prover's commitments from Prover (via Put) and make them accessible (i.e. kind of fix the API...)
	responsesChan chan kyber.Scalar  // to extract the prover's responses from Prover (via Put)
	challengeChan chan kyber.Scalar // to give challenges to the Prover (via PubRand)
}

// TODO doc + QUESTION convention for newSomething returning a pointer ? => seems that yes !
func newClientProverCtx(suite Suite, n int) *clientProverCtx {
	return &clientProverCtx{
		SuiteProof: newSuiteProof(suite),
		commitsChan: make(chan kyber.Point, n),   // Point FIFO of size n = #clients in auth. group = #predicates in OrProof
		responsesChan: make(chan kyber.Scalar, n), // Scalar FIFO of size n = size n = #clients in auth. group = #predicates in OrProof
		challengeChan: make(chan kyber.Scalar, n),
	}
}

// "Send message to verifier" or make the prover's messages available to our/user code
// satisfy the proof.ProverContext interface, TODO doc, not meant to be used by "user" code see commitments and repsonses methods
// QUESTION is there a way/pattern to implement interface with public methods while making them private...? guess no but..
func (cpCtx clientProverCtx) Put(message interface{}) error {
	// TODO or type switch maybe prettier
	if msg, ok := message.(kyber.Point); ok {
		// send commitment to user code (via commits channel via commitments method)
		cpCtx.commitsChan <- msg  // blocks if chan full which should never happen (buffer should have the right size, #clients/predicates in the OrPred)
		log.Info("client proof, " + strconv.Itoa(len(cpCtx.commitsChan)) + " prover's message/commit available in channel ..")
		return nil
	} else if msg, ok := message.(kyber.Scalar); ok {
		cpCtx.responsesChan <- msg  // block if chan full which should never happen (buffer should have the right size, #clients/predicates in the OrPred)
		return nil
	} else {
		return errors.New("clientProverCtx.Put: commit message from prover not of type kyber.Point neither kyber.Scalar (" + fmt.Sprint("%T", message) + ")")
	}
}

// retrieve the Prover's first message/commitments t=(t1.0, t1.10, t1.11, ... , tn.0, tn.10, tn.11 )
func (cpCtx clientProverCtx) commitments() (commitments []kyber.Point)  {
	// TODO maybe mechanism that check this is called only once
	commitments = make([]kyber.Point, cap(cpCtx.commitsChan))
	for i := range commitments {
		// get commitment from Prover (via commits channel via Put method)
		commitments[i] = <- cpCtx.commitsChan  // blocks if chan empty (should never happens), (unless chan closed by sending side which is not the case)
	}
	// TODO would have liked to range on chan and have sending side close the chan, but not possible since would need to
	// TODO re-create another channel to later send/receive the final message of prover...maybe see if ok
	return
}

func (cpCtx clientProverCtx) responses() []kyber.Scalar {
	// TODO communicate with prover via chan via put
	return nil
}

// Get public randomness / challenge from verifier/chan
// TODO doc, not meant to be used by "user" code see receiveChallenge method
func (cpCtx clientProverCtx) PubRand(message ...interface{}) error { // QUESTION why not a slice instead of variadic stuff + why not kyber.Scalar instead of interface{} ?
	if len(message) != 1 {
		return errors.New("clientProverCtx.PubRand called with less or more than one arg")
	}

	// get challenge from remote verifier (via challenge channel via receiveChallenge method)
	// blocks until challenge received from remote verifier and sent in channel by user code (via receiveChallenge method)
	challenge := <- cpCtx.challengeChan

	// TODO or type switch maybe prettier
	if scalar, ok := message[0].(kyber.Scalar); ok {
		scalar.Set(challenge)
		return nil
	} else {
		return errors.New("clientProverCtx.PubRand called with type " + fmt.Sprintf("%T", message) + " instead of kyber.Scalar")
	}
}

// send challenge to Prover
func (cpCtx clientProverCtx) receiveChallenges(challenges []kyber.Scalar) {
	// TODO maybe mechanism that check this is called only once

	// TODO
	// send challenge to Prover (via challenge channel via PubRand method)
	cpCtx.challengeChan <- challenge  // blocks if channel not empty which should never be the case
	// TODO log
}

// Get private randomness
// TODO kind of copy pasted from hasprovercontext => see how/where to share code/helpers
// TODO doc, not meant to be used by "user" code
func (cpCtx clientProverCtx) PriRand(message ...interface{}) error {
	if err := cpCtx.Read(&cipherStreamReader{cpCtx.RandomStream()}, message...); err != nil {
		return fmt.Errorf("clientProverCtx.PriRand: error reading random stream: %v", err.Error())
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

// FIXME name and interface
// TODO two choices either have everything inside (pick server at random etc..)
// TODO or have server "location/address whatever and channel" setup outside (need a chan to transmit server responses to
// TODO or accept lambdas to call to communicate with server
// TODO code in this function...)
// TODO QUESTION attach it to a receiver ? (don't see the point but I have seen it in kyber)
func prove(context authenticationContext, client client, tagAndCommitments initialTagAndCommitments) clientProof {
	//construct the proof.Prover for client's PK and its proof.ProverContext
	prover := newClientProver(context, client, tagAndCommitments)
	proverCtx := newClientProverCtx(suite, len(context.g.x))

	//3-move interaction with server
	//	start the proof.Prover and proof machinery in new goroutine
	var P clientProof
	go func() {
		if err := prover(proverCtx); err != nil {
			// TODO onet.log something
		}
	}()
	//	get initial commitments from Prover
	commits := proverCtx.commitments()
	P.t = commits

	//	forward them to random remote server/verifier (over *anon.* circuit etc.. !!)
	// TODO pick random server and find its location
	// TODO establish anon circuit/channel to server (if I choose do this here, maybe better call user supplied lambda) separation of concerns !
	// TODO encode and send commits
	// QUESTION TODO FIXME, will need to have kind of a directory mapping servers to their IP/location don't currently know how this is addressed in cothority onet
	// QUESTION can I have a quick intro on how I to do this using onet ? or should I do my own cuisine ?

	//	receive challenge from remote server (over *anon.* circuit etc.. !!)
	// TODO receive and decode master challenge (or call user supplied lambda interface whatever)
	var challenge kyber.Scalar

	// build all the "sub" challenges
	// TODO
	var challenges []kyber.Scalar

	//	forward challenges to Prover in order to continue the proof process
	proverCtx.receiveChallenges(challenges)

	//	get final responses from Prover
	responses := proverCtx.responses()

	// forward them to remote server
	// TODO (or call user supplied lambda or interface whatever)

	// build the clientProof (as of DAGA paper) and return it to caller
	return clientProof{
		cs: challenge,
		t: commits,
		c: challenges,
		r: responses,
	}
}

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
