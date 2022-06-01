package tcpconnectanalyzer

import (
	"time"

	"github.com/Kindling-project/kindling/collector/analyzer"
	"github.com/Kindling-project/kindling/collector/analyzer/tcpconnectanalyzer/internal"
	"github.com/Kindling-project/kindling/collector/component"
	"github.com/Kindling-project/kindling/collector/consumer"
	conntrackerpackge "github.com/Kindling-project/kindling/collector/metadata/conntracker"
	"github.com/Kindling-project/kindling/collector/model"
	"github.com/Kindling-project/kindling/collector/model/constlabels"
	"github.com/Kindling-project/kindling/collector/model/constnames"
	"github.com/hashicorp/go-multierror"
	"go.uber.org/zap"
)

const Type analyzer.Type = "tcpconnectanalyzer"

type TcpConnectAnalyzer struct {
	config        *Config
	nextConsumers []consumer.Consumer
	conntracker   conntrackerpackge.Conntracker

	eventChannel   chan *model.KindlingEvent
	connectMonitor *internal.ConnectMonitor

	stopCh chan bool

	telemetry *component.TelemetryTools
}

func New(cfg interface{}, telemetry *component.TelemetryTools, consumers []consumer.Consumer) analyzer.Analyzer {
	config := cfg.(*Config)
	ret := &TcpConnectAnalyzer{
		config:        config,
		nextConsumers: consumers,
		telemetry:     telemetry,
		eventChannel:  make(chan *model.KindlingEvent, config.ChannelSize),
		stopCh:        make(chan bool),

		connectMonitor: internal.NewConnectMonitor(telemetry.Logger),
	}
	conntracker, err := conntrackerpackge.NewConntracker(nil)
	if err != nil {
		telemetry.Logger.Warn("Conntracker cannot work as expected:", zap.Error(err))
	}
	ret.conntracker = conntracker
	newSelfMetrics(telemetry.MeterProvider, ret.connectMonitor)
	return ret
}

func (a *TcpConnectAnalyzer) ConsumableEvents() []string {
	return []string{
		constnames.ConnectEvent,
		constnames.TcpConnectEvent,
		constnames.TcpSetStateEvent,
		constnames.WriteEvent,
		constnames.WritevEvent,
		constnames.SendMsgEvent,
		constnames.SendToEvent,
	}
}

// Start initializes the analyzer
func (a *TcpConnectAnalyzer) Start() error {
	go func() {
		scanTcpStateTicker := time.NewTicker(time.Duration(a.config.WaitEventSecond/3) * time.Second)
		for {
			select {
			case <-scanTcpStateTicker.C:
				a.trimConnectionsWithTcpStat()
			case event := <-a.eventChannel:
				a.consumeChannelEvent(event)
			case <-a.stopCh:
				// Only trim the connections expired. For those unfinished, we leave them
				// unchanged and just shutdown this goroutine.
				a.trimConnectionsWithTcpStat()
				return
			}
		}
	}()
	return nil
}

// ConsumeEvent gets the event from the previous component
func (a *TcpConnectAnalyzer) ConsumeEvent(event *model.KindlingEvent) error {
	a.eventChannel <- event
	return nil
}

func (a *TcpConnectAnalyzer) consumeChannelEvent(event *model.KindlingEvent) {
	var (
		connectStats *internal.ConnectionStats
		err          error
	)

	switch event.Name {
	case constnames.ConnectEvent:
		if !event.IsTcp() {
			return
		}
		connectStats, err = a.connectMonitor.ReadInConnectExitSyscall(event)
	case constnames.TcpConnectEvent:
		connectStats, err = a.connectMonitor.ReadInTcpConnect(event)
	case constnames.TcpSetStateEvent:
		connectStats, err = a.connectMonitor.ReadInTcpSetState(event)
	case constnames.WriteEvent:
		fallthrough
	case constnames.WritevEvent:
		fallthrough
	case constnames.SendToEvent:
		fallthrough
	case constnames.SendMsgEvent:
		if filterRequestEvent(event) {
			return
		}
		connectStats, err = a.connectMonitor.ReadSendRequestSyscall(event)
	}

	if err != nil {
		a.telemetry.Logger.Debug("Cannot update connection stats:", zap.Error(err))
		return
	}
	// Connection is not established yet
	if connectStats == nil {
		return
	}

	dataGroup := a.generateMetricGroup(connectStats)
	a.passThroughConsumers(dataGroup)
}

func filterRequestEvent(event *model.KindlingEvent) bool {
	if event.Category != model.Category_CAT_NET {
		return true
	}

	ctx := event.GetCtx()
	if ctx == nil || ctx.GetThreadInfo() == nil {
		return true
	}
	fd := ctx.GetFdInfo()
	if fd == nil {
		return true
	}
	if fd.GetProtocol() != model.L4Proto_TCP {
		return true
	}
	if fd.GetSip() == nil || fd.GetDip() == nil {
		return true
	}

	return false
}

func (a *TcpConnectAnalyzer) trimExpiredConnStats() {
	connStats := a.connectMonitor.TrimExpiredConnections(a.config.WaitEventSecond * 3)
	for _, connStat := range connStats {
		dataGroup := a.generateMetricGroup(connStat)
		a.passThroughConsumers(dataGroup)
	}
}

func (a *TcpConnectAnalyzer) trimConnectionsWithTcpStat() {
	connStats := a.connectMonitor.TrimConnectionsWithTcpStat(a.config.WaitEventSecond)
	for _, connStat := range connStats {
		dataGroup := a.generateMetricGroup(connStat)
		a.passThroughConsumers(dataGroup)
	}
}

func (a *TcpConnectAnalyzer) passThroughConsumers(dataGroup *model.DataGroup) {
	var retError error
	for _, nextConsumer := range a.nextConsumers {
		err := nextConsumer.Consume(dataGroup)
		if err != nil {
			retError = multierror.Append(retError, err)
		}
	}
	if retError != nil {
		a.telemetry.Logger.Warn("Error happened while passing through processors:", zap.Error(retError))
	}
}

func (a *TcpConnectAnalyzer) generateMetricGroup(connectStats *internal.ConnectionStats) *model.DataGroup {
	labels := model.NewAttributeMap()
	// The connect events always come from the client-side
	labels.AddBoolValue(constlabels.IsServer, false)
	if connectStats.ConnectSyscall != nil {
		labels.AddStringValue(constlabels.ContainerId, connectStats.ConnectSyscall.GetContainerId())
	}
	labels.AddIntValue(constlabels.Errno, int64(connectStats.Code))
	if connectStats.StateMachine.GetCurrentState() == internal.Closed {
		lastState := connectStats.StateMachine.GetLastState()
		if lastState == internal.Success {
			labels.AddBoolValue(constlabels.Success, true)
		} else {
			labels.AddBoolValue(constlabels.Success, false)
		}
	} else if connectStats.StateMachine.GetCurrentState() == internal.Success {
		labels.AddBoolValue(constlabels.Success, true)
	} else {
		labels.AddBoolValue(constlabels.Success, false)
	}
	srcIp := connectStats.ConnKey.SrcIP
	dstIp := connectStats.ConnKey.DstIP
	srcPort := connectStats.ConnKey.SrcPort
	dstPort := connectStats.ConnKey.DstPort
	labels.UpdateAddStringValue(constlabels.SrcIp, srcIp)
	labels.UpdateAddStringValue(constlabels.DstIp, dstIp)
	labels.UpdateAddIntValue(constlabels.SrcPort, int64(srcPort))
	labels.UpdateAddIntValue(constlabels.DstPort, int64(dstPort))
	dNatIp, dNatPort := a.findDNatTuple(srcIp, uint64(srcPort), dstIp, uint64(dstPort))
	labels.AddStringValue(constlabels.DnatIp, dNatIp)
	labels.AddIntValue(constlabels.DnatPort, dNatPort)

	countValue := model.NewIntMetric(constnames.TcpConnectTotalMetric, 1)
	durationValue := model.NewIntMetric(constnames.TcpConnectDurationMetric, connectStats.GetConnectDuration())

	retDataGroup := model.NewDataGroup(
		constnames.TcpConnectMetricGroupName,
		labels,
		connectStats.EndTimestamp,
		countValue, durationValue)

	return retDataGroup
}

func (a *TcpConnectAnalyzer) findDNatTuple(sIp string, sPort uint64, dIp string, dPort uint64) (string, int64) {
	dNat := a.conntracker.GetDNATTupleWithString(sIp, dIp, uint16(sPort), uint16(dPort), 0)
	if dNat == nil {
		return "", -1
	}
	dNatIp := dNat.ReplSrcIP.String()
	dNatPort := dNat.ReplSrcPort
	return dNatIp, int64(dNatPort)
}

// Shutdown cleans all the resources used by the analyzer
func (a *TcpConnectAnalyzer) Shutdown() error {
	a.stopCh <- true
	return nil
}

// Type returns the type of the analyzer
func (a *TcpConnectAnalyzer) Type() analyzer.Type {
	return Type
}
