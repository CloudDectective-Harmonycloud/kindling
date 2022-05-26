package prometheusexporter

import (
	"github.com/Kindling-project/kindling/collector/consumer/exporter/otelexporter/defaultadapter"
	"github.com/Kindling-project/kindling/collector/model"
	"go.uber.org/zap"
)

func (p *prometheusExporter) Consume(dataGroup *model.DataGroup) error {
	if dataGroup == nil {
		// no need consume
		return nil
	}
	if ce := p.telemetry.Logger.Check(zap.DebugLevel, "exporter receives a dataGroup: "); ce != nil {
		ce.Write(
			zap.String("dataGroup", dataGroup.String()),
		)
	}

	if adapters, ok := p.adapters[dataGroup.Name]; ok {
		for i := 0; i < len(adapters); i++ {
			results, err := adapters[i].Adapt(dataGroup)
			if err != nil {
				p.telemetry.Logger.Error("Failed to adapt dataGroup", zap.Error(err))
			}
			if results != nil && len(results) > 0 {
				p.Export(results)
			}
		}
	} else {
		results, err := p.defaultAdapter.Adapt(dataGroup)
		if err != nil {
			p.telemetry.Logger.Error("Failed to adapt dataGroup", zap.Error(err))
		}
		if results != nil && len(results) > 0 {
			p.Export(results)
		}
	}
	return nil
}

func (p *prometheusExporter) Export(results []*defaultadapter.AdaptedResult) {
	for i := 0; i < len(results); i++ {
		result := results[i]
		switch result.ResultType {
		case defaultadapter.Metric:
			p.exportMetric(result)
		default:
			p.telemetry.Logger.Error("Unexpected ResultType", zap.String("type", string(result.ResultType)))
		}
		result.Free()
	}
}

func (p *prometheusExporter) exportMetric(result *defaultadapter.AdaptedResult) {
	p.collector.recordMetricGroups(model.NewDataGroup("", result.AttrsMap, result.Timestamp, result.Metrics...))
}
