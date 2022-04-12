package aggregateprocessor

type Config struct {
	// TODO: Expose filters to configuration
	// Unable to work now.
	FilterLabels []string `mapstructure:"filter_labels"`
	// The unit is second.
	TickerInterval int `mapstructure:"ticker_interval"`

	AggregateKindMap map[string][]AggregatedKindConfig `mapstructure:"aggregate_kind_map"`
	SamplingRate     *SampleConfig                     `mapstructure:"sampling_rate"`
}

type AggregatedKindConfig struct {
	OutputName string `mapstructure:"output_name"`
	Kind       string `mapstructure:"kind"`
}

type SampleConfig struct {
	NormalData int `mapstructure:"normal_data"`
	SlowData   int `mapstructure:"slow_data"`
	ErrorData  int `mapstructure:"error_data"`
}

func NewDefaultConfig() *Config {
	ret := &Config{
		FilterLabels:   make([]string, 0),
		TickerInterval: 5,
		AggregateKindMap: map[string][]AggregatedKindConfig{
			"request_count":      {{Kind: "sum"}},
			"request_total_time": {{Kind: "sum"}, {Kind: "avg", OutputName: "request_total_time_avg"}},
			"request_io":         {{Kind: "sum"}},
			"response_io":        {{Kind: "sum"}},
			// tcp
			"kindling_tcp_rtt_microseconds":  {{Kind: "last"}},
			"kindling_tcp_retransmit_total":  {{Kind: "sum"}},
			"kindling_tcp_packet_loss_total": {{Kind: "sum"}},
		},
		SamplingRate: &SampleConfig{
			NormalData: 0,
			SlowData:   100,
			ErrorData:  100,
		},
	}
	return ret
}
