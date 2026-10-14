//go:build linux

package deployansible

import (
	"errors"
	"net"
	"os"
	"syscall"
)

func sendRequest(conn *net.UnixConn, data []byte, files []*os.File) error {
	descriptors := make([]int, 0, len(files))
	for _, file := range files {
		descriptors = append(descriptors, int(file.Fd()))
	}
	var rights []byte
	if len(descriptors) > 0 {
		rights = syscall.UnixRights(descriptors...)
	}
	written, _, err := conn.WriteMsgUnix(data, rights, nil)
	if err != nil || written != len(data) {
		return errors.New("controller submission failed")
	}
	return nil
}

func receiveRequest(conn *net.UnixConn) ([]byte, []*os.File, error) {
	data := make([]byte, 1<<20)
	control := make([]byte, syscall.CmsgSpace(3*4))
	count, controlCount, flags, _, err := conn.ReadMsgUnix(data, control)
	if err != nil {
		return nil, nil, err
	}
	messages, err := syscall.ParseSocketControlMessage(control[:controlCount])
	if err != nil {
		return nil, nil, err
	}
	var files []*os.File
	for _, message := range messages {
		if message.Header.Level != syscall.SOL_SOCKET || message.Header.Type != syscall.SCM_RIGHTS {
			continue
		}
		descriptors, err := syscall.ParseUnixRights(&message)
		if err != nil {
			closeInputs(files)
			return nil, nil, err
		}
		for _, descriptor := range descriptors {
			syscall.CloseOnExec(descriptor)
			files = append(files, os.NewFile(uintptr(descriptor), "submitted-input"))
		}
	}
	if flags&(syscall.MSG_CTRUNC|syscall.MSG_TRUNC) != 0 || len(files) > 3 {
		closeInputs(files)
		return nil, nil, errors.New("invalid submitted descriptors")
	}
	return data[:count], files, nil
}
