package daga_login

import (
	"bytes"
	"encoding/gob"
	"errors"
	"github.com/dedis/student_18_daga/sign/daga"
	"io/ioutil"
)

func ReadContext(path string) (*daga.AuthenticationContext, error) {
	if data, err := ioutil.ReadFile(path); err != nil {
		return nil, errors.New("readContext:" + err.Error())
	} else {
		var netContext NetContextEd25519
		var buffer bytes.Buffer
		buffer.Write(data)
		if err = gob.NewDecoder(&buffer).Decode(&netContext); err != nil {
			return nil, errors.New("readContext:" + err.Error())
		} else {
			if context, err := netContext.NetDecode(daga.NewSuiteEC()); err != nil {
				return nil, errors.New("readContext:" + err.Error())
			} else {
				return context, nil
			}
		}
	}
}
