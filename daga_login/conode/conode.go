// Conode is the main binary for running a Cothority server.
// A conode can participate in various distributed protocols using the
// *onet* library as a network and overlay library and the *dedis/kyber*
// library for all cryptographic primitives.
// Basically, you first need to setup a config file for the server by using:
//
//  ./conode setup
//
// Then you can launch the daemon with:
//
//  ./conode
//
package main

import (
	"github.com/dedis/student_18_daga/sign/daga"
	"os"
	"path"

	"github.com/dedis/onet/app"
	"github.com/dedis/onet/cfgpath"
	"github.com/dedis/onet/log"
	"gopkg.in/urfave/cli.v1"
	// Import your service:
	_ "github.com/dedis/cothority/status/service"
	_ "github.com/dedis/student_18_daga/daga_login/service"
	//_ "github.com/dedis/pulsar/randhound/service"
	// Here you can import any other needed service for your conode.
	// For example, if your service needs cosi available in the server
	// as well, uncomment this:
	//_ "github.com/dedis/cothority/cosi/service"
)

func main() {
	cliApp := cli.NewApp()
	cliApp.Usage = "basic file for an app TODO"
	cliApp.Version = "0.1"

	cliApp.Commands = []cli.Command{
		{
			Name:    "setup",
			Aliases: []string{"s"},
			Usage:   "Setup server configuration (interactive)",
			Action: func(c *cli.Context) error {
				if c.String("config") != "" {
					log.Fatal("[-] Configuration file option cannot be used for the 'setup' command")
				}
				if c.String("debug") != "" {
					log.Fatal("[-] Debug option cannot be used for the 'setup' command")
				}
				app.InteractiveConfig(daga.NewSuiteEC(), cliApp.Name)
				return nil
			},
		},
		{
			Name:  "server",
			Usage: "Start cothority server",
			Action: func(c *cli.Context) {
				runServer(c)
			},
		},
	}
	cliApp.Flags = []cli.Flag{
		cli.IntFlag{
			Name:  "debug, d",
			Value: 0,
			Usage: "debug-level: 1 for terse, 5 for maximal",
		},
		cli.StringFlag{
			Name:  "config, c",
			Value: path.Join(cfgpath.GetConfigPath(cliApp.Name), app.DefaultServerConfig), // TODO verify that it is still working (replaced a "magic app name" with what I think is populated by default app name)
			Usage: "Configuration file of the server",
		},
	}
	cliApp.Before = func(c *cli.Context) error {
		log.SetDebugVisible(c.Int("debug"))
		return nil
	}

	log.ErrFatal(cliApp.Run(os.Args))
}

func runServer(c *cli.Context) error {
	app.RunServer(c.GlobalString("config"))
	return nil
}
