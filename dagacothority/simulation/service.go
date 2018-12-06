package main

import (
	"github.com/BurntSushi/toml"
	"github.com/dedis/cothority_template"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/simul/monitor"
)

/*
 * Defines the simulation for the daga service
 */

func init() {
	onet.SimulationRegister("DagaServiceSimulation", NewSimulationService)
}

// SimulationService implements the onet.Simulation interface
type SimulationService struct {
	onet.SimulationBFTree
	// TODO not sure if I can/need reuse it..
	//  .don't see why I would use a tree to test at the service level..
	//  is it to define the topology of the simulation network ?? or is it the same kind of tree that is used to run the protocols...
}

// NewSimulationService returns the new simulation, where all fields are
// initialised using the toml config-file
func NewSimulationService(config string) (onet.Simulation, error) {
	simService := &SimulationService{}
	_, err := toml.Decode(config, simService)
	if err != nil {
		return nil, err
	}
	return simService, nil
}

// Setup creates a roster from `hosts` and the tree used for that simulation
// implements the Simulation interface.
func (s *SimulationService) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
	sc := &onet.SimulationConfig{}
	s.CreateRoster(sc, hosts, 2000)
	// QUESTION WTF tree? for what purpose ???? I want to simulate a service that will create the tree it needs for the protocols it launches.
	//  ok seems that if I don't create a Tree I can't call SimulationBFTree.Node (remains to know if I need to call it.......)
	//err := s.CreateTree(sc)
	//if err != nil {
	//	return nil, err
	//}
	return sc, nil
}

// Node can be used to initialize each node before it will be run
// by the server. Here we call the 'Node'-method of the
// SimulationBFTree structure which will load the roster- and the
// tree-structure to speed up the first round.
func (s *SimulationService) Node(config *onet.SimulationConfig) error {
	// TODO maybe initializes some contexts in the services's states, but else I don't see why I would need to use such method
	//index, _ := config.Roster.Search(config.Server.ServerIdentity.ID)
	//if index < 0 {
	//	log.Fatal("Didn't find this node in roster")
	//}
	//log.Lvl3("Initializing node-index", index)
	//return s.SimulationBFTree.Node(config)
	return nil
}

// Run is used on the destination machines and runs a number of
// rounds
func (s *SimulationService) Run(config *onet.SimulationConfig) error {
	size := config.Tree.Size()
	log.Lvl2("Size is:", size, "rounds:", s.Rounds)
	c := template.NewClient()
	for round := 0; round < s.Rounds; round++ {
		log.Lvl1("Starting round", round)
		round := monitor.NewTimeMeasure("round")
		resp, err := c.Clock(config.Roster)
		log.ErrFatal(err)
		if resp.Time <= 0 {
			log.Fatal("0 time elapsed")
		}
		round.Record()
	}
	return nil
}
