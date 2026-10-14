//go:build !linux

package deployansible

import (
	"errors"
	"net"
	"os"
)

func sendRequest(_ *net.UnixConn, _ []byte, _ []*os.File) error {
	return errors.New("controller requires Linux descriptor passing")
}
func receiveRequest(_ *net.UnixConn) ([]byte, []*os.File, error) {
	return nil, nil, errors.New("controller requires Linux descriptor passing")
}
