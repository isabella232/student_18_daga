package service

import (
	"github.com/dedis/kyber"
	"github.com/dedis/student_18_daga/daga_login"
)

/* holds the data structures/types needed by the DAGA service */
// TODO QUESTION: for now export everything to be able to "store" it using onet (not safe + i'm not ok with it but what to do ? don't use onet storage ? or what ??)

type State map[daga_login.ServiceID]ServiceState // per 3rd party service state (admin. infos, contexts etc..)
type LinkageTag kyber.Point

type SubscriberState struct {
	Key kyber.Point // current public key of the anon subscriber (!= key in auth. context) used to log-in (challenge response) QUESTION can very well use another "challenge response tool" instead like password hash techniques
	// TODO track # of auth, add TTL etc..
}

// hold the state related to a 3rd-party service
type ServiceState struct { // TODO better name to not confuse with daga service or don't care and use godoc for that
	ID daga_login.ServiceID
	// FIXME name, address contact infos etc.. (use OpenPGP identity that has everything needed)
	adminKey      kyber.Point                           // to auth. service owner/admin (verify signatures) FIXME use OpenPGP infrastructure and web of trust, cached version of key retrieved from key servers etc..verify trust etc..
	ContextStates map[daga_login.ContextID]ContextState // maps 3rd-party services to their (potentially multiple) auth. context(s)
}

// hold the state related to an auth. context (the context, the daga server, the
// TODO maybe rename or reorganize
type ContextState struct {
	Context          daga_login.Context             // the daga auth. context
	SubscriberStates map[LinkageTag]SubscriberState // maps clients/subscriber tags (anonymousId) to their auth. state (# of auth. during round, current "anon key", timestamp last auth. / key TTL etc.. TODO better name
	DagaServer       daga_login.NetServer           // daga 'server' for this daga auth. context (contains server's per-round secret etc..)
}
