/*
* TODO FIXME
* This is a template for creating an app.
 */
package main

import (
	"errors"
	"fmt"
	"github.com/dedis/kyber"
	"github.com/dedis/onet"
	"github.com/dedis/onet/app"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/dedis/student_18_daga/daga_login"
	"github.com/dedis/student_18_daga/sign/daga"
	"gopkg.in/urfave/cli.v1"
	"os"
	"strconv"
)

var suite = daga.NewSuiteEC()

func main() {
	cliApp := cli.NewApp()
	cliApp.Usage = "Used for building other apps."
	cliApp.Version = "0.1"
	//groupsDef := "the group-definition-file"
	cliApp.Commands = []cli.Command{
		{
			Name:        "auth",
			Description: "create and send a new daga auth. request on behalf of CLIENT under CONTEXT",
			Usage:       "auth CLIENT CONTEXT",
			Aliases:     []string{"a"},
			ArgsUsage:   "CLIENT the client definition file, CONTEXT the context definition file",
			Action:      cmdAuth,
		},
		{
			Name:        "createContext",
			Description: "setup NUMCLIENTS clients, a daga auth. context (with all the nodes in ROSTER as daga servers) and save them to current directory under client%d.bin and context.bin",
			Usage:       "setup NUMCLIENTS ROSTER",
			Aliases:     []string{"c"},
			ArgsUsage:   "NUMCLIENTS the number of clients, ROSTER the public group definition file",
			Action:      cmdSetup,
		},
	}
	cliApp.Flags = []cli.Flag{
		cli.IntFlag{
			Name:  "debug, d",
			Value: 0,
			Usage: "debug-level: 1 for terse, 5 for maximal",
		},
	}
	cliApp.Before = func(c *cli.Context) error {
		log.SetDebugVisible(c.Int("debug"))
		return nil
	}
	log.ErrFatal(cliApp.Run(os.Args))
}

// setup c clients, and a daga auth context served by cothority defined in roster and save them to FS
// all the servers/nodes in the provided group/roster will be part of the generated Context
// TODO clean rewrite is still used later (notably the err handling)
func cmdSetup(c *cli.Context) error {
	// read number of clients
	numClients := readInt(c.Args(), "Please give the number of DAGA clients you want to configure")

	// read roster
	roster := readRoster(c.Args().Tail())

	// to encode, to save to FS
	network.RegisterMessages(daga_login.Context{}, daga_login.NetClient{})

	// create daga clients and collect their public keys
	clients := make([]daga.Client, numClients)
	subscribers := make([]kyber.Point, 0, len(clients))
	for i, _ := range clients {
		if client, err := daga.NewClient(suite, i, nil); err != nil {
			return err
		} else {
			clients[i] = client
			subscribers = append(subscribers, client.PublicKey())
		}
	}

	// create AdminClient (3rd-party service admin) to call daga API endpoint
	serviceProvider := daga_login.NewAdminClient()

	var errs []error
	// create and register context with running daga cothority and save it to FS
	if context, err := serviceProvider.CreateContext(subscribers, roster); err != nil {
		return err
	} else {
		//save context to new protobuf bin file TODO or whatever, maybe better toml config files
		errs = append(errs, saveToFile("./context.bin", context)) // TODO remove magic strings
	}

	// save clients conf to disk
	netClients, err := daga_login.NetEncodeClients(clients)
	errs = append(errs, err)
	for i, netClient := range netClients {
		errs = append(errs, saveToFile(fmt.Sprintf("./client%d.bin", i), &netClient)) // TODO remove magic strings
	}

	for _, err := range errs {
		if err != nil {
			return err
		}
	}

	fmt.Println("done!")
	return nil
}

// authenticate
func cmdAuth(c *cli.Context) error {
	log.Info("Auth command")

	// fetch args
	clientPath := readString(c.Args(), "Please give the client definition file of the client you want to run")
	contextPath := readString(c.Args().Tail(), "Please give the context definition file of the authentication context")
	// cmdAuth only needs an auth. context, and the client identity in context (basically an index and a privatekey)
	// TODO for now accept context and private client toml (kinda... net bin for now)
	network.RegisterMessages(daga_login.NetClient{}, daga_login.Context{})
	client, err := daga_login.ReadClient(clientPath)
	if err != nil {
		return err
	}

	context, err := daga_login.ReadContext(contextPath)
	if err != nil {
		return err
	}

	// call DAGA API endpoint
	tag, err := client.Auth(*context)
	if err != nil {
		return fmt.Errorf("failed to authenticate user %d: %s", client.Index(), err)
	}
	log.Infof("final linkage tag (pseudonymousID) of user %d under the provided context: %v", client.Index(), tag)
	return nil
}

func readRoster(args cli.Args) *onet.Roster {
	name := readString(args, "Please give the public roster/group-file as argument")
	f, err := os.Open(name)
	log.ErrFatal(err, "Couldn't open group definition file (roster)")
	group, err := app.ReadGroupDescToml(f)
	log.ErrFatal(err, "Error while reading group definition file (roster)", err)
	if len(group.Roster.List) == 0 {
		log.ErrFatalf(err, "Empty entity or invalid group definition in: %s",
			name)
	}
	return group.Roster
}

func readString(args cli.Args, errStr string) string {
	str := args.First()
	if str == "" {
		log.Fatal(errStr)
	}
	return str
}

func readInt(args cli.Args, errStr string) int {
	intStr := readString(args, errStr)
	if i, err := parseInt(intStr); err != nil {
		log.Fatal(errStr + ": " + err.Error())
		return -1
	} else {
		return i
	}
}

func parseInt(intStr string) (int, error) {
	if index, err := strconv.Atoi(intStr); err == nil {
		return index, nil
	} else {
		return -1, err
	}
}

// msg must be a pointer to data type registered to the network library
func saveToFile(path string, msg interface{}) error {
	bytes, err := network.Marshal(msg)
	if err != nil {
		return errors.New("saveToFile: " + err.Error())
	}
	fd, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return errors.New("saveToFile: " + err.Error())
	}
	_, err = fd.Write(bytes)
	if err != nil {
		return errors.New("saveToFile: " + err.Error())
	}
	return nil
}
