package protocols_test

import (
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/student_18_daga/sign/daga"
)

var tSuite = daga.NewSuiteEC()

// Used for tests
var testServiceID onet.ServiceID

const testServiceName = "dummyDagaService"

func init() {
	var err error
	testServiceID, err = onet.RegisterNewService(testServiceName, NewDummyService)
	log.ErrFatal(err)
}

// dummyService to provide state to the protocol instances
type DummyService struct {
	// We need to embed the ServiceProcessor, so that incoming messages
	// are correctly handled.
	*onet.ServiceProcessor

	// Has to be initialised by the tests
	DagaServer daga.Server
	NewRootProtocol func()
}

// returns a new dummyService
func NewDummyService(c *onet.Context) (onet.Service, error) {
	s := &DummyService{
		ServiceProcessor: onet.NewServiceProcessor(c),
	}
	return s, nil
}