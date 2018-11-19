package service

import (
	"errors"
	"fmt"
	"github.com/dedis/kyber"
	"github.com/dedis/student_18_daga/daga_login"
	"gopkg.in/satori/go.uuid.v1"
)

/* holds the data structures/types needed by the DAGA service */
// TODO QUESTION: for now export everything to be able to "store" it using onet (not safe + i'm not ok with it but what to do ? don't use onet storage ? or what ??)

type State map[daga_login.ServiceID]*ServiceState // per 3rd party service state (admin. infos, contexts etc..)
type LinkageTag kyber.Point

type SubscriberState struct {
	Key kyber.Point // current public key of the anon subscriber (!= key in auth. context) used to log-in (challenge response, can very well use another "challenge response tool" instead like password hash techniques
	// => Linus doesn't like the idea (indeed service needs to ask daga for mappings etc..but on the other hand more flexible and support different kind of "authentication/challenge-response" while not tying the thing to DAGA protocol)
	// TODO track # of auth, add TTL etc..
}

// TODO/FIXME for now keep current structure while keeping in mind that we decided to retrieve group from byzcoin pop instance and to put contexts/service state in a daga instance on the chain
// sketch both architectures and compare advantages/drawbacks

// hold the state related to a 3rd-party service
type ServiceState struct { // TODO better name to not confuse with daga service or don't care and use godoc for that
	ID daga_login.ServiceID
	// FIXME name, address contact infos etc.. (use OpenPGP identity that has everything needed)
	adminKey      kyber.Point                           // to auth. service owner/admin (verify signatures) FIXME use OpenPGP infrastructure and web of trust, cached version of key retrieved from key servers etc..verify trust etc..
	ContextStates map[daga_login.ContextID]*ContextState // maps 3rd-party services to their (potentially multiple) auth. context(s)
}

func (ss *ServiceState) contextState(cid daga_login.ContextID) (*ContextState, error) {
	if cid == daga_login.ContextID(uuid.Nil) {
		return nil, errors.New("contextState: Nil/Zero ID")
	}
	if contextState, ok := ss.ContextStates[cid]; !ok {
		return nil, fmt.Errorf("contextState: unknown context ID: %v", cid)
	} else {
		return contextState, nil
	}
}

// hold the state related to an auth. context (the context, the daga server, ...
// TODO maybe rename or reorganize
type ContextState struct {
	Context          daga_login.Context             // the daga auth. context
	// see lab notes, we currently decided to not use that for the login service (but IMHO we should keep it..)
	//SubscriberStates map[LinkageTag]SubscriberState // maps clients/subscriber tags (anonymousId) to their auth. state (# of auth. during round, current "anon key", timestamp last auth. / key TTL etc.. TODO better name
	DagaServer       daga_login.NetServer           // daga 'server' for this daga auth. context (contains server's per-round secret etc..)
}
