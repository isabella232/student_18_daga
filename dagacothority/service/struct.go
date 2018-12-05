package service

import (
	"errors"
	"fmt"
	"github.com/dedis/kyber"
	"github.com/dedis/student_18_daga/dagacothority"
	"gopkg.in/satori/go.uuid.v1"
	"sync"
)

/* holds the data structures/types needed by the DAGA service */
// TODO QUESTION: for now export everything to be able to "store" it using onet (not safe + i'm not ok with it but what to do ? don't use onet storage ? or what ??)

type State struct {
	// Mutex: since state can be/is accessed from multiple go rountines at a time
	// (some protocol instances obtain such ability, see dagacontextgeneration.protocol.ChildSetup)
	// and that concurrent write/read access are not ok.

	// TODO/optimization consider using a sync.Map instead since our usage seems to fit its purposes
	// The sync.Map type is optimized for two common use cases: (1) when the entry for a given
	// key is only ever written once but read many times, as in caches that only grow,
	// or (2) when multiple goroutines read, write, and overwrite entries for disjoint
	// sets of keys. In these two cases, use of a Map may significantly reduce lock
	// contention compared to a Go map paired with a separate Mutex or RWMutex.
	// TODO or another ready key value store...

	sync.RWMutex
	data map[dagacothority.ServiceID]*ServiceState // per 3rd party service state (admin. infos, contexts etc..)
}

func NewState() State {
	// FIXME exported since used in api_test but would be better to find another solution than exporting things only to setup tests
	//  maybe move the "service related setup test boilerplate" in service package...this would help resolve the duplicated code in api_test and service tests too
	return State{
		data: map[dagacothority.ServiceID]*ServiceState{},
	}
}

func (s *State) createIfNotExisting(sid dagacothority.ServiceID) {
	s.Lock()
	defer s.Unlock()
	if _, present := s.data[sid]; !present {
		s.data[sid] = &ServiceState{
			ID:            sid,
			ContextStates: make(map[dagacothority.ContextID]*ContextState),
			adminKey:      nil, // TODO, openPGP, fetch key from keyserver
		}
	}
}

// get returns the 3rd-party related state or an error if 3rd-party service unknown.
// !always use it to read service's state, (direct access to the state map can lead to race conditions
// since the storage can be accessed/updated from multiple goroutines (protocol instances))!
func (s *State) get(sid dagacothority.ServiceID) (*ServiceState, error) {
	s.RLock()
	defer s.RUnlock()

	if serviceState, ok := s.data[sid]; !ok {
		return nil, fmt.Errorf("unknown service ID: %v", sid)
	} else {
		return serviceState, nil
	}
}

// Set updates the 3rd-party related state, safe wrapper for write access to the Storage.State "map"
// !always use it to write service's state (add a ServiceState), (direct access to the storage's state map can lead to race conditions
// since the storage can be accessed/updated from multiple goroutines (protocol instances))!
func (s *State) Set(key dagacothority.ServiceID, value *ServiceState) {
	// FIXME exported since used in api_test but would be better to find another solution than exporting things only to setup tests
	s.Lock()
	defer s.Unlock()
	s.data[key] = value
}

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
	ID dagacothority.ServiceID
	// FIXME name, address contact infos etc.. (use OpenPGP identity that has everything needed)
	adminKey      kyber.Point                               // to auth. service owner/admin (verify signatures) FIXME use OpenPGP infrastructure and web of trust, cached version of key retrieved from key servers etc..verify trust etc..
	ContextStates map[dagacothority.ContextID]*ContextState // maps 3rd-party services to their (potentially multiple) auth. context(s)
}

func (ss *ServiceState) contextState(cid dagacothority.ContextID) (*ContextState, error) {
	if cid == dagacothority.ContextID(uuid.Nil) {
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
	Context dagacothority.Context // the daga auth. context
	// see lab notes, we currently decided to not use that for the login service (but IMHO we should keep it..)
	//SubscriberStates map[LinkageTag]SubscriberState // maps clients/subscriber tags (anonymousId) to their auth. state (# of auth. during round, current "anon key", timestamp last auth. / key TTL etc.. TODO better name
	DagaServer dagacothority.NetServer // daga 'server' for this daga auth. context (contains server's per-round secret etc..)
}
