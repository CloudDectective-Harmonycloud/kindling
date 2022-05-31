package internal

import (
	"fmt"

	"github.com/Kindling-project/kindling/collector/model"
)

type connCode int

const (
	noError connCode = iota
	// See <errno.h> in Linux
	einprogress = -115
	ealready    = -114
	eisconn     = -106
	eintr       = -4
)

const (
	established = "01"
	synSent     = "02"
	synRecv     = "03"
	finWait1    = "04"
	finWait2    = "05"
	timeWait    = "06"
	close       = "07"
	closeWait   = "08"
	lastAck     = "09"
	listen      = "0A"
	closing     = "0B"
)

type ConnectionStats struct {
	pid              uint32
	ConnKey          ConnKey
	StateMachine     *StateMachine
	InitialTimestamp uint64
	EndTimestamp     uint64
	Code             connCode

	ConnectSyscall *model.KindlingEvent
	TcpConnect     *model.KindlingEvent
	TcpSetState    *model.KindlingEvent
}

func (c *ConnectionStats) GetConnectDuration() int64 {
	return int64(c.EndTimestamp - c.InitialTimestamp)
}

type ConnKey struct {
	SrcIP   string
	SrcPort uint32
	DstIP   string
	DstPort uint32
}

func (k *ConnKey) toSocketKey() SocketKey {
	return SocketKey{
		LocalAddr: k.SrcIP,
		LocalPort: uint64(k.SrcPort),
		RemAddr:   k.DstIP,
		RemPort:   uint64(k.DstPort),
	}
}

func (k *ConnKey) String() string {
	return fmt.Sprintf("src: %s:%d, dst: %s:%d", k.SrcIP, k.SrcPort, k.DstIP, k.DstPort)
}

const (
	Inprogress StateType = "inprogress"
	Success    StateType = "success"
	Failure    StateType = "failure"
	Closed     StateType = "closed"

	tcpConnectError              EventType = "tcp_connect_negative"
	tcpConnectNoError            EventType = "tcp_connect_zero"
	tcpSetStateToEstablished     EventType = "tcp_set_state_to_established"
	tcpSetStateFromEstablished   EventType = "tcp_set_state_from_established"
	connectExitSyscallSuccess    EventType = "connect_exit_syscall_zero"
	connectExitSyscallFailure    EventType = "connect_exit_syscall_failure"
	connectExitSyscallNotConcern EventType = "connect_exit_syscall_not_concern"
	expiredEvent                 EventType = "expired_event"
)

func createStatesResource() StatesResource {
	return StatesResource{
		Inprogress: State{
			eventsMap: map[EventType]StateType{
				tcpConnectNoError:            Inprogress,
				tcpConnectError:              Failure,
				tcpSetStateToEstablished:     Success,
				tcpSetStateFromEstablished:   Success,
				connectExitSyscallSuccess:    Success,
				connectExitSyscallFailure:    Failure,
				connectExitSyscallNotConcern: Inprogress,
				expiredEvent:                 Failure,
			},
			callback: nil,
		},
		Success: {
			eventsMap: map[EventType]StateType{
				tcpSetStateToEstablished:     Success,
				tcpSetStateFromEstablished:   Closed,
				connectExitSyscallSuccess:    Success,
				connectExitSyscallNotConcern: Success,
				expiredEvent:                 Closed,
			},
			callback: func(connStats *ConnectionStats, connMap map[ConnKey]*ConnectionStats) *ConnectionStats {
				return connStats
			},
		},
		Failure: {
			eventsMap: map[EventType]StateType{
				connectExitSyscallFailure:    Failure,
				connectExitSyscallNotConcern: Failure,
				expiredEvent:                 Closed,
			},
			callback: func(connStats *ConnectionStats, connMap map[ConnKey]*ConnectionStats) *ConnectionStats {
				return connStats
			},
		},
		Closed: {
			eventsMap: map[EventType]StateType{},
			callback: func(connStats *ConnectionStats, connMap map[ConnKey]*ConnectionStats) *ConnectionStats {
				delete(connMap, connStats.ConnKey)
				return nil
			},
		},
	}
}
