package DAGADEXConnector

import (
	"github.com/dexidp/dex/connector"
)

type DAGAConnector struct {
	titi int
}

// NewDAGAConnector returns a dex callback connector. that use DAGA to authenticate users
func NewDAGAConnector() connector.Connector {

	// TODO
	return connector.CallbackConnector(nil)
}
