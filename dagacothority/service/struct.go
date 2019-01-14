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

// State holds everything the daga service needs to remember
// for now everything exported to be able to "store" it using onet bbolt facilities
// TODO flatten, hold only contextsStates (the only thing DAGA needs to do its real work) and use other ways, in user code etc.. to keep 3rd-party service data
//  up to now, in my mind, the daga service/cothority was/could be the direct interlocutor of 3rd party services/RP => need way to authenticate their requests if not open service etc.
//  but it is probably better to set the daga service to its minimum (authentication) and use it to build other primitives.
//  (this raise again the question of context creation, we still need ways to individually at the node level decide if a context creation request is ok => see idea described in authrequest method of service)
//  see if state cannot be completely removed, (see comments related to state and context validation in service.go)
//  but before following that path, see what we need to implement context evolution features.
type State struct {
	// Mutex needed since state can be/is accessed from multiple go rountines at a time
	// (some protocol instances obtain ability to update state, see dagacontextgeneration.protocol.ChildSetup)
	// and that concurrent map write/read access are not ok.

	// TODO/optimization consider using a sync.Map instead since our usage seems to fit its purposes
	// "The sync.Map type is optimized for two common use cases: (1) when the entry for a given
	// key is only ever written once but read many times, as in caches that only grow,
	// or (2) when multiple goroutines read, write, and overwrite entries for disjoint
	// sets of keys. In these two cases, use of a Map may significantly reduce lock
	// contention compared to a Go map paired with a separate Mutex or RWMutex."
	// TODO or another ready-made key value store...or not

	sync.RWMutex
	Data map[dagacothority.ServiceID]*ServiceState // per 3rd party service state (admin. infos, contexts etc..)
}

// newState returns a newly allocated State struct
func newState() State {
	return State{
		Data: make(map[dagacothority.ServiceID]*ServiceState),
	}
}

func (s *State) createIfNotExisting(sid dagacothority.ServiceID) {
	s.Lock()
	defer s.Unlock()
	if _, present := s.Data[sid]; !present {
		s.Data[sid] = &ServiceState{
			ID:            sid,
			ContextStates: make(map[dagacothority.ContextID]*ContextState),
			adminKey:      nil,
		}
	}
}

// get returns the 3rd-party related state or an error if 3rd-party service unknown.
// !always use it to read service's state, (direct access to the state map can lead to race conditions
// since the storage can be accessed/updated from multiple goroutines (protocol instances))!
func (s *State) get(sid dagacothority.ServiceID) (*ServiceState, error) {
	s.RLock()
	defer s.RUnlock()

	if serviceState, ok := s.Data[sid]; !ok {
		return nil, fmt.Errorf("unknown service ID: %v", sid)
	} else {
		return serviceState, nil
	}
}

// set updates the 3rd-party related state, safe wrapper for write access to the Storage.state "map"
// !always use it to write service's state (add a ServiceState), (direct access to the storage's state map can lead to race conditions
// since the storage can be accessed/updated from multiple goroutines (protocol instances))!
func (s *State) set(key dagacothority.ServiceID, value *ServiceState) {
	s.Lock()
	defer s.Unlock()
	s.Data[key] = value
}

//type LinkageTag kyber.Point

//type SubscriberState struct {
//	to track # of auth during round/context, add TTL etc.. ?
//	 those are things that can be useful to revoke context etc.. see when context evolution features fixed and implemented
//}

// ServiceState holds the state related to a 3rd-party service (notably the contexts)
// TODO see comment above for State => probably get rid of it + decide when authentication of 3rd party decided and implemented
type ServiceState struct { // not to be confused with daga service
	ID dagacothority.ServiceID
	//+ name, address contact infos etc..
	adminKey      kyber.Point                               // to auth. service owner/admin (verify signatures)
	// TODO use OpenPGP infrastructure and web of trust,
	//  cached version of key retrieved from key servers etc..verify trust etc..or see the better options envisioned and commented in service.go
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

// ContextState holds the state related to an auth. context (the context, the daga server, ...
type ContextState struct {
	Context dagacothority.Context // the daga auth. context

	//SubscriberStates map[LinkageTag]SubscriberState // maps clients/subscriber tags (anonymousId) to their auth. state (# of auth. during round, current "anon key", timestamp last auth. / key TTL etc.. TODO better name
	DagaServer dagacothority.NetServer // daga 'server' for this daga auth. context (contains server's per-round secret etc..)
}
