package otelexporter

import (
	"context"
	"github.com/Kindling-project/kindling/collector/model"
	"github.com/Kindling-project/kindling/collector/model/constnames"
	"github.com/Kindling-project/kindling/collector/model/constvalues"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	apitrace "go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

func (e *OtelExporter) Consume(gaugeGroup *model.GaugeGroup) error {
	if gaugeGroup == nil {
		// no need consume
		return nil
	}
	gaugeGroupReceiverCounter.Add(context.Background(), 1, attribute.String("name", gaugeGroup.Name))
	if ce := e.telemetry.Logger.Check(zap.DebugLevel, "exporter receives a gaugeGroup: "); ce != nil {
		ce.Write(
			zap.String("gaugeGroup", gaugeGroup.String()),
		)
	}

	var hasResult = false
	for i := 0; i < len(e.adapters); i++ {
		results, _ := e.adapters[i].Adapt(gaugeGroup)
		if results != nil && len(results) > 0 {
			e.Export(results, e.adapters[i])
			hasResult = true
		}
	}
	if hasResult == false {
		if ce := e.telemetry.Logger.Check(zap.DebugLevel, "No adapter can deal with this gaugeGroup"); ce != nil {
			ce.Write(
				zap.String("gaugeGroup", gaugeGroup.String()),
			)
		}
	}
	return nil
}

func (e *OtelExporter) Export(results []*AdaptedResult, adapter Adapter) {
	for i := 0; i < len(results); i++ {
		result := results[i]
		switch result.ResultType {
		case Metric:
			e.exportMetric(result, adapter)
		case Trace:
			e.exportTrace(result)
		default:
			e.telemetry.Logger.Error("Unexpected ResultType", zap.String("type", string(result.ResultType)))
		}
	}
}

func (e *OtelExporter) exportTrace(result *AdaptedResult) {
	if e.defaultTracer != nil && e.cfg.AdapterConfig.NeedTraceAsResourceSpan {
		_, span := e.defaultTracer.Start(
			context.Background(),
			constvalues.SpanInfo,
			apitrace.WithAttributes(result.Attrs...),
		)
		span.End()
	} else if e.defaultTracer != nil && e.cfg.AdapterConfig.NeedTraceAsResourceSpan {
		e.telemetry.Logger.Error("send span failed: this exporter can not support Span Data", zap.String("exporter", e.cfg.ExportKind))
	}
}

func (e *OtelExporter) exportMetric(result *AdaptedResult, adapter Adapter) {
	// Get Measurement
	measurements := make([]metric.Measurement, 0, len(result.Gauges))
	for s := 0; s < len(result.Gauges); s++ {
		gauge := result.Gauges[s]
		var metricName string
		switch result.RenameRule {
		case ServerMetrics:
			metricName = constnames.ToKindlingNetMetricName(gauge.Name, true)
		case TopologyMetrics:
			metricName = constnames.ToKindlingNetMetricName(gauge.Name, false)
		default:
			metricName = gauge.Name
		}
		if metricKind, ok := e.findInstrumentKind(metricName); ok && metricKind != MAGaugeKind {
			measurements = append(measurements, e.instrumentFactory.getInstrument(metricName, metricKind).Measurement(gauge.Value))
		} else if ok && metricKind == MAGaugeKind {
			preAggGaugeGroupLabels, err := adapter.Transform(result.OriginData)
			if err != nil {
				e.telemetry.Logger.Error("Transform failed", zap.Error(err))
			} else {
				err2 := e.instrumentFactory.recordLastValue(metricName, &model.GaugeGroup{
					Name:      PreAggMetric,
					Values:    []*model.Gauge{{metricName, gauge.Value}},
					Labels:    preAggGaugeGroupLabels,
					Timestamp: result.OriginData.Timestamp,
				})
				if err2 != nil {
					e.telemetry.Logger.Error("Failed to record Gauge", zap.Error(err2))
				}
			}
		}
	}
	if len(measurements) > 0 {
		e.instrumentFactory.meter.RecordBatch(context.Background(), result.Attrs, measurements...)
	}
}