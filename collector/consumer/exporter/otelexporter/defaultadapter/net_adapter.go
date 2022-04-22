package defaultadapter

import (
	"github.com/Kindling-project/kindling/collector/consumer/exporter/otelexporter"
	"github.com/Kindling-project/kindling/collector/model"
	"github.com/Kindling-project/kindling/collector/model/constlabels"
	"github.com/Kindling-project/kindling/collector/model/constnames"
	"github.com/Kindling-project/kindling/collector/model/constvalues"
	"go.opentelemetry.io/otel/attribute"
)

type NetGaugeGroupAdapter struct {
	*NetAdapterManager
	*NetAdapterConfig
}

type NetAdapterConfig struct {
	StoreTraceAsMetric bool
	StoreTraceAsSpan   bool
	StorePodDetail     bool
	StoreExternalSrcIP bool
}

func (n *NetGaugeGroupAdapter) Adapt(gaugeGroup *model.GaugeGroup) ([]*otelexporter.AdaptedResult, error) {
	if gaugeGroup.Name != constnames.AggregatedNetRequestGaugeGroup && gaugeGroup.Name != constnames.SingleNetRequestGaugeGroup {
		// skip non net gaugeGroup
		return nil, nil
	}

	if gaugeGroup.Name == constnames.AggregatedNetRequestGaugeGroup {
		return n.dealWithPreAggGaugeGroups(gaugeGroup)
	} else {
		return n.dealWithSingleGaugeGroup(gaugeGroup)
	}
}

func (n *NetGaugeGroupAdapter) Transform(gaugeGroup *model.GaugeGroup) (*model.AttributeMap, error) {
	// For NetAdapter , only need to transform the traceAsMetric , maybe we should add some mark to decide how to transform later
	return n.traceToMetricAdapter.transform(gaugeGroup)
}

func (n *NetGaugeGroupAdapter) dealWithSingleGaugeGroup(gaugeGroup *model.GaugeGroup) ([]*otelexporter.AdaptedResult, error) {
	var requestTotalTimeIndex = -1
	for i := 0; i < len(gaugeGroup.Values); i++ {
		if gaugeGroup.Values[i].Name == constvalues.RequestTotalTime {
			requestTotalTimeIndex = i
			break
		}
	}
	if requestTotalTimeIndex == -1 {
		// No requestTotalTimeGauge
		return nil, nil
	}
	results := make([]*otelexporter.AdaptedResult, 0, 2)
	if n.StoreTraceAsSpan && isSlowOrError(gaugeGroup) {
		if attrs, err := n.traceToSpanAdapter.adapt(gaugeGroup); err != nil {
			return nil, err
		} else {
			results = append(results, &otelexporter.AdaptedResult{
				ResultType: otelexporter.Trace,
				Attrs:      attrs,
				Gauges:     []*model.Gauge{gaugeGroup.Values[requestTotalTimeIndex]},
				RenameRule: otelexporter.KeepOrigin,
				OriginData: gaugeGroup,
			})
		}
	}
	if n.StoreTraceAsMetric {
		results = append(results, &otelexporter.AdaptedResult{
			ResultType: otelexporter.Metric,
			Attrs:      nil,
			Gauges: []*model.Gauge{{
				Name:  constnames.TraceAsMetric,
				Value: gaugeGroup.Values[requestTotalTimeIndex].Value,
			}},
			RenameRule: otelexporter.KeepOrigin,
			OriginData: gaugeGroup,
		})
	}

	return results, nil
}

func (n *NetGaugeGroupAdapter) dealWithPreAggGaugeGroups(gaugeGroup *model.GaugeGroup) ([]*otelexporter.AdaptedResult, error) {
	results := make([]*otelexporter.AdaptedResult, 0, 4)
	var requestTotalIndex = -1
	for i := 0; i < len(gaugeGroup.Values); i++ {
		if gaugeGroup.Values[i].Name == constvalues.RequestCount {
			requestTotalIndex = i
			break
		}
	}

	isServer := gaugeGroup.Labels.GetBoolValue(constlabels.IsServer)
	srcNamespace := gaugeGroup.Labels.GetStringValue(constlabels.SrcNamespace)
	if n.StoreExternalSrcIP && srcNamespace == constlabels.ExternalClusterNamespace && isServer {
		externalAdapterCache := n.detailTopologyAdapter
		if externalTopology, err := n.createNetMetricResults(gaugeGroup, externalAdapterCache, requestTotalIndex); err != nil {
			return nil, err
		} else {
			results = append(results, externalTopology...)
		}
	}

	var metricAdapterCache [2]*adapterCache
	if n.StorePodDetail {
		if isServer {
			metricAdapterCache = n.detailEntityAdapter
		} else {
			metricAdapterCache = n.detailTopologyAdapter
		}
	} else {
		if isServer {
			metricAdapterCache = n.aggEntityAdapter
		} else {
			metricAdapterCache = n.aggTopologyAdapter
		}
	}
	if metrics, err := n.createNetMetricResults(gaugeGroup, metricAdapterCache, requestTotalIndex); err != nil {
		return nil, err
	} else {
		results = append(results, metrics...)
	}
	return results, nil
}

func (n *NetGaugeGroupAdapter) createNetMetricResults(gaugeGroup *model.GaugeGroup, adapter [2]*adapterCache, requestTotalIndex int) (tmpResults []*otelexporter.AdaptedResult, err error) {
	values := gaugeGroup.Values
	// TODO deal with error
	attrsCommon, _ := adapter[0].adapt(gaugeGroup)
	if requestTotalIndex == -1 {
		tmpResults = make([]*otelexporter.AdaptedResult, 0, 1)
		// for request count
		tmpResults = append(tmpResults, &otelexporter.AdaptedResult{
			ResultType: otelexporter.Metric,
			Attrs:      attrsCommon,
			Gauges:     gaugeGroup.Values,
			RenameRule: otelexporter.TopologyMetrics,
			OriginData: gaugeGroup,
		})
	} else {
		tmpResults = make([]*otelexporter.AdaptedResult, 0, 2)
		// for request count
		tmpResults = append(tmpResults, &otelexporter.AdaptedResult{
			ResultType: otelexporter.Metric,
			Attrs:      attrsCommon,
			Gauges:     append(values[:requestTotalIndex], values[requestTotalIndex+1:]...),
			RenameRule: otelexporter.TopologyMetrics,
			OriginData: gaugeGroup,
		})
		// TODO deal with error
		attrsWithSlow, _ := adapter[1].adapt(gaugeGroup)
		tmpResults = append(tmpResults, &otelexporter.AdaptedResult{
			ResultType: otelexporter.Metric,
			Attrs:      attrsWithSlow,
			Gauges:     []*model.Gauge{values[requestTotalIndex]},
			RenameRule: otelexporter.TopologyMetrics,
			OriginData: gaugeGroup,
		})
	}
	return
}

type NetAdapterManager struct {
	detailEntityAdapter   [2]*adapterCache
	aggEntityAdapter      [2]*adapterCache
	detailTopologyAdapter [2]*adapterCache
	aggTopologyAdapter    [2]*adapterCache
	traceToSpanAdapter    *adapterCache
	traceToMetricAdapter  *adapterCache
}

func createNetAdapterManager(constLabels []attribute.KeyValue) *NetAdapterManager {
	// TODO deal Error
	aggEntityAdapterWithIsSlow, _ := newAdapterBuilder(entityMetricDicList,
		[][]dictionary{isSlowDicList}).
		withExtraLabels(entityProtocol, updateProtocolKey).
		withConstLabels(constLabels).
		build()

	detailEntityAdapterWithIsSlow, _ := newAdapterBuilder(entityMetricDicList,
		[][]dictionary{entityInstanceMetricDicList, entityDetailMetricDicList, isSlowDicList}).
		withExtraLabels(entityProtocol, updateProtocolKey).
		withConstLabels(constLabels).
		build()

	aggTopologyAdapterWithIsSlow, _ := newAdapterBuilder(topologyMetricDicList,
		[][]dictionary{isSlowDicList}).
		withExtraLabels(topologyProtocol, updateProtocolKey).
		withAdjust(RemoveDstPodInfoForNonExternal()).
		withConstLabels(constLabels).
		build()

	detailTopologyAdapterWithIsSlow, _ := newAdapterBuilder(topologyMetricDicList,
		[][]dictionary{topologyInstanceMetricDicList, topologyDetailMetricDicList, isSlowDicList}).
		withExtraLabels(topologyProtocol, updateProtocolKey).
		withAdjust(ReplaceDstIpOrDstPortByDNat()).
		withConstLabels(constLabels).
		build()

	aggEntityAdapter, _ := newAdapterBuilder(entityMetricDicList,
		[][]dictionary{}).
		withExtraLabels(entityProtocol, updateProtocolKey).
		withConstLabels(constLabels).
		build()

	detailEntityAdapter, _ := newAdapterBuilder(entityMetricDicList,
		[][]dictionary{entityInstanceMetricDicList, entityDetailMetricDicList}).
		withExtraLabels(entityProtocol, updateProtocolKey).
		withConstLabels(constLabels).
		build()

	aggTopologyAdapter, _ := newAdapterBuilder(topologyMetricDicList,
		[][]dictionary{}).
		withExtraLabels(topologyProtocol, updateProtocolKey).
		withAdjust(RemoveDstPodInfoForNonExternal()).
		withConstLabels(constLabels).
		build()

	detailTopologyAdapter, _ := newAdapterBuilder(topologyMetricDicList,
		[][]dictionary{topologyInstanceMetricDicList, topologyDetailMetricDicList}).
		withExtraLabels(topologyProtocol, updateProtocolKey).
		withAdjust(ReplaceDstIpOrDstPortByDNat()).
		withConstLabels(constLabels).
		build()

	traceToSpanAdapter, _ := newAdapterBuilder(topologyMetricDicList,
		[][]dictionary{topologyInstanceMetricDicList, SpanDicList}).
		withExtraLabels(spanProtocol, updateProtocolKey).
		withValueToLabels(traceSpanStatus, getTraceSpanStatusLabels).
		//withAdjust(ReplaceDstIpOrDstPortByDNat()).
		withConstLabels(constLabels).
		build()

	traceToMetricAdapter, _ := newAdapterBuilder(topologyMetricDicList,
		[][]dictionary{topologyInstanceMetricDicList, topologyDetailMetricDicList}).
		withExtraLabels(entityProtocol, updateProtocolKey).
		withValueToLabels(traceStatus, getTraceStatusLabels).
		//withAdjust(ReplaceDstIpOrDstPortByDNat()).
		withConstLabels(constLabels).
		build()

	return &NetAdapterManager{
		aggEntityAdapter:      [2]*adapterCache{aggEntityAdapter, aggEntityAdapterWithIsSlow},
		detailEntityAdapter:   [2]*adapterCache{detailEntityAdapter, detailEntityAdapterWithIsSlow},
		aggTopologyAdapter:    [2]*adapterCache{aggTopologyAdapter, aggTopologyAdapterWithIsSlow},
		detailTopologyAdapter: [2]*adapterCache{detailTopologyAdapter, detailTopologyAdapterWithIsSlow},
		traceToSpanAdapter:    traceToSpanAdapter,
		traceToMetricAdapter:  traceToMetricAdapter,
	}
}

func NewNetAdapter(
	customLabels []attribute.KeyValue,
	config *NetAdapterConfig,
) *NetGaugeGroupAdapter {
	return &NetGaugeGroupAdapter{
		NetAdapterManager: createNetAdapterManager(customLabels),
		NetAdapterConfig:  config,
	}
}

func isSlowOrError(g *model.GaugeGroup) bool {
	return g.Labels.GetBoolValue(constlabels.IsSlow) || g.Labels.GetBoolValue(constlabels.IsError)
}