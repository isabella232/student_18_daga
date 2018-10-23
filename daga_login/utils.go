package daga_login

import (
	"errors"
	"github.com/dedis/onet/network"
	"github.com/dedis/student_18_daga/sign/daga"
	"io/ioutil"
)

func ReadContext(path string) (*daga.AuthenticationContext, error) {
	if bytes, err := ioutil.ReadFile(path); err != nil {
		return nil, errors.New("readContext:" + err.Error())
	} else {
		if _, msg, err := network.Unmarshal(bytes, suite); err != nil {
			return nil, errors.New("readContext:" + err.Error())
		} else {
			if netContext, ok := msg.(*NetContext); !ok {
				return nil, errors.New("readContext: type assertion error")
			} else {
				return netContext.NetDecode()
			}
		}
	}
}
