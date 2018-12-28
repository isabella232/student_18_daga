package main

import (
	"github.com/dedis/onet/simul"
	// Service needs to be imported here to be instantiated.
	_ "github.com/dedis/student_18_daga/dagacothority/service"
)

func main() {
	simul.Start()
}
