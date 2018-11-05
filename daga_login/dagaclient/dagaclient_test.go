package main

import (
	"testing"

	"github.com/dedis/onet/log"
)

// It is useful for Onet applications to run code before and after the
// Go test framework, for example in order to configure logging, to
// set a global time limit, and to check for leftover goroutines.
//
// See:
//   - https://godoc.org/testing#hdr-Main
//   - https://godoc.org/github.com/dedis/onet/log#MainTest
func TestMain(m *testing.M) {
	log.MainTest(m)
}
