/*
* TODO FIXME
* This is a template for creating an app.
 */
package main

import (
	bytes2 "bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/util/encoding"
	"github.com/dedis/onet/app"
	"github.com/dedis/onet/log"
	"github.com/dedis/student_18_daga/daga_login"
	"github.com/dedis/student_18_daga/sign/daga"
	"gopkg.in/urfave/cli.v1"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

func main() {
	cliApp := cli.NewApp()
	cliApp.Usage = "Used for building other apps."
	cliApp.Version = "0.1"
	groupsDef := "the group-definition-file"
	cliApp.Commands = []cli.Command{
		{
			Name:      "time",
			Usage:     "measure the time to contact all nodes",
			Aliases:   []string{"t"},
			ArgsUsage: groupsDef,
			Action:    cmdTime,
		},
		{
			Name:      "counter",
			Usage:     "return the counter",
			Aliases:   []string{"c"},
			ArgsUsage: groupsDef,
			Action:    cmdCounter,
		},
		{
			Name: 		"login",
			Usage:		"create and send a new daga auth. request",
			Aliases:	[]string{"l"},
			ArgsUsage:	groupsDef + " and the index (in auth. context) of the client being run",
			Action:		cmdLogin,
		},
		{// FIXME, for now here but move where more appropriate if still used later
			Name:       "setup",
			Usage:		"setup c clients, servers and a daga auth. context and save them to FS TODO",
			Aliases: 	[]string{"s"},
			ArgsUsage:	groupsDef + ", c the number of clients",
			Action: 	cmdSetup,
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

// Returns the time needed to contact all nodes.
func cmdTime(c *cli.Context) error {
	log.Info("Time command")
	group := readGroup(c.Args())
	client, _ := daga_login.NewClient(0, nil)
	resp, err := client.Clock(group.Roster)
	if err != nil {
		return errors.New("When asking the time: " + err.Error())
	}
	log.Infof("Children: %d - Time spent: %f", resp.Children, resp.Time)
	return nil
}

// Returns the number of calls.
func cmdCounter(c *cli.Context) error {
	log.Info("Counter command")
	group := readGroup(c.Args())
	client, _ := daga_login.NewClient(0, nil)
	counter, err := client.Count(group.Roster.RandomServerIdentity())
	if err != nil {
		return errors.New("When asking for counter: " + err.Error())
	}
	log.Info("Number of requests:", counter)
	return nil
}

// setup c clients, servers (from the configs found in ./mycononodes/cox) and a daga auth context and save them to FS
// current hack way to provide daga context to the participants
func cmdSetup(c *cli.Context) error {
	// read group/roster
	group := readGroup(c.Args())
	// read the number of clients
	numClients := readInt(c.Args().Tail(), "Please give the number of daga clients you want to configure")

	// read the servers keys from roster and private config files
	// TODO here assume that the conode description are always something_N in roster and N maps to ./mycononodes/coN
	// (it is the case when using run_conodes.sh) maybe add possibility to specify basepath and delimiter or map[description]index
	// FIXME dumb, instead here generate the private.toml files from scratch using infos from daga.GenerateContext (but guess I'll lose compatibility with other facilities, bash tests etc..)
	// FIXME + more sound since now I don't check the suite in toml but... if want same functionnality as the one given by run_conodes.sh will took time...
	// FIXME or quickfix check suite ..
	serverKeys := make([]kyber.Scalar, 0, len(group.Description))
	for _, description := range group.Description {
		iStr := description[strings.IndexByte(description, '_')+1:]
		if i, err := strconv.Atoi(iStr); err != nil {
			return errors.New("failed to get server index out of \"" + description + "\": " + err.Error())
		} else {
			path := "./myconodes/co" + iStr + "/private.toml"
			config := &app.CothorityConfig{}
			_, err := toml.DecodeFile(path, config)
			if err != nil {
				return fmt.Errorf("failed to parse the cothority config of server %d: %s", i, err)
			}
			privateKey, err := encoding.StringHexToScalar(daga.NewSuiteEC(), config.Private)  // let's hope that this will work (the suite)
			serverKeys = append(serverKeys, privateKey)
		}
	}
	// create daga clients servers and context and save them to FS
	var errs []error
	var buffer bytes2.Buffer
	encoder := gob.NewEncoder(&buffer)
	clients, servers, context, err := daga.GenerateContext(daga.NewSuiteEC(), numClients, serverKeys)
	errs = append(errs, err)
	//save context to new toml or json file or protobuf bin file or whatever TODO FIXME for now everything in 3 files, out of scope for now (i'm hacking around to satisfy the assumptions of daga, but we will need protocols to setup a context, with start stop clientregister serverregister etc..))
	netContext, err := daga_login.NetEncodeContext(context)
	errs = append(errs, err)
	errs = append(errs, encoder.Encode(netContext))
	err = saveToFile("./context.bin", buffer.Bytes()) // TODO remove magic strings
	errs = append(errs, err)
	buffer.Reset()
	// save clients and servers conf to disk
	netClients, err := daga_login.NetEncodeClients(clients)
	errs = append(errs, err)
	errs = append(errs, encoder.Encode(netClients))
	saveToFile("./clients.bin", buffer.Bytes()) // TODO remove magic strings
	buffer.Reset()
	netServers, err := daga_login.NetEncodeServers(servers)
	errs = append(errs, err)
	errs = append(errs, encoder.Encode(netServers))
	errs = append(errs, gob.NewEncoder(&buffer).Encode(netServers))
	saveToFile("./servers.bin", buffer.Bytes()) // TODO remove magic strings
	buffer.Reset()
	for _, err := range errs {
		if err != nil {
			log.Fatal(err)
		}
	}

	// TODO servers will load their conf in service.tryload
	// (or QUESTION: better to keep vanilla conode and everything in other conf files loaded in service startup
	// 	   QUESTION: or modify conode (in a cothority-compatible way) to add other private infos and conf it needs in private.toml ??
	// or mix of both ..
	// TODO now move quick and dirty, implement the minimal to have a daga setup working to start implementing the protocols
	fmt.Println("done!")
	return nil
}

// authenticate
func cmdLogin(c *cli.Context) error {
	log.Info("Login command")
	group := readGroup(c.Args())
	index := readInt(c.Args().Tail(), "Please give the index (in auth. context) of the client you want to run")
	// TODO same issues and questions as in setup => need to fix the frame/goals of my work, now I'm hacking to continue the developpment
	// TODO all of this is not needed when there are facilities to create/join an auth. context, cmdLogin needs only an index and a privatekey
	// FIXME but now I'll accept only index and parse private key from file(s) generated by setup (maybe I should move these meta things in a bash wrapper,  but..)
	privateKey, err := readPrivateKey(index, "./clients.bin")

	client, _ := daga_login.NewClient(index, privateKey)
	context, err := daga_login.ReadContext("./context.bin") // TODO remove magic value
	if err != nil {
		log.Fatal(err)
	}
	tag, err := client.Login(*context, group.Roster)
	if err != nil {
		return errors.New("Failed to login: " + err.Error())
	}
	log.Info("final linkage tag:", tag)
	return nil
}

func readGroup(args cli.Args) *app.Group {
	name := args.First()
	if name == "" {
		log.Fatal("Please give the group-file as argument")
	}
	f, err := os.Open(name)
	log.ErrFatal(err, "Couldn't open group definition file")
	group, err := app.ReadGroupDescToml(f)
	log.ErrFatal(err, "Error while reading group definition file", err)
	if len(group.Roster.List) == 0 {
		log.ErrFatalf(err, "Empty entity or invalid group defintion in: %s",
			name)
	}
	return group
}

func readInt(args cli.Args, errStr string) int {
	intStr := args.First()
	if intStr == "" {
		log.Fatal(errStr)
	}
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

func saveToFile(path string, bytes []byte) error {
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

//helper I use in stead of a key and context manager...FIXME...see related comments above
// TODO consider panic early instead of error prop. to isolate quickly source of problem if any
func readPrivateKey(index int, path string) (kyber.Scalar, error) {
	if bytes, err := ioutil.ReadFile(path); err != nil {
		return nil, errors.New("readPrivateKey:" + err.Error())
	} else {
		var netClients []daga_login.NetClient
		var buffer bytes2.Buffer
		buffer.Write(bytes)
		if err = gob.NewDecoder(&buffer).Decode(netClients); err != nil {
			return nil, errors.New("readPrivateKey:" + err.Error())
		} else {
			if clients, err := daga_login.NetDecodeClients(netClients); err != nil {
				return nil, errors.New("readPrivateKey:" + err.Error())
			} else {
				return clients[index].PrivateKey(), nil
			}
		}
	}
}
