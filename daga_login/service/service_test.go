package service

//import (
//	"github.com/dedis/kyber/suites"
//	"github.com/dedis/onet"
//	"github.com/dedis/onet/log"
//	"github.com/stretchr/testify/require"
//	"testing"
//)
//
//var tSuite = suites.MustFind("Ed25519")
//
//func TestMain(m *testing.M) {
//	log.MainTest(m)
//}
//
//func TestService_PKClient(t *testing.T) {
//	local := onet.NewTCPTest(tSuite)
//	// generate 5 hosts, they don't connect, they process messages, and they
//	// don't register the tree or entitylist
//	hosts, roster, _ := local.GenTree(5, true)
//	defer local.CloseAll()
//
//	services := local.GetServices(hosts, templateID)
//
//	// QUESTION again not well testable... I'd need to mock/stub/fake some parts of the service (provide its storage, or fake tryload..)
//
//	//for _, s := range services {
//	//	// setup:
//	//	log.Lvl2("Sending request to", s)
//	//	resp, err := s.(*Service).Clock(
//	//		&daga_login.Clock{Roster: roster},
//	//	)
//	//	require.Nil(t, err)
//	//	require.Equal(t, resp.Children, len(roster.List))
//	//}
//}
//
//func TestService_Count(t *testing.T) {
//	local := onet.NewTCPTest(tSuite)
//	// generate 5 hosts, they don't connect, they process messages, and they
//	// don't register the tree or entitylist
//	hosts, roster, _ := local.GenTree(5, true)
//	defer local.CloseAll()
//
//	services := local.GetServices(hosts, templateID)
//
//	for _, s := range services {
//		log.Lvl2("Sending request to", s)
//		resp, err := s.(*Service).Clock(
//			&daga_login.Clock{Roster: roster},
//		)
//		require.Nil(t, err)
//		require.Equal(t, resp.Children, len(roster.List))
//		count, err := s.(*Service).Count(&daga_login.Count{})
//		require.Nil(t, err)
//		require.Equal(t, 1, count.Count)
//	}
//}
