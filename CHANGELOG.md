# Changelog
### Notes
1. All notable changes to this project will be documented in this file.
2. Records in this file are not identical to the title of their Pull Requests. A detailed description is necessary for understanding what changes are and why they are made.

## Unreleased 
### Enhancements
- Print logs when subscribing to events. Print a warning message if there is no event the agent subscribes to. ([#290](https://github.com/CloudDectective-Harmonycloud/kindling/pull/290))
- Allow the collector run in the non-Kubernetes environment by setting the option `enable` `false` under the `k8smetadataprocessor` section. ([#285](https://github.com/CloudDectective-Harmonycloud/kindling/pull/285))
- Add a new environment variable: IS_PRINT_EVENT. When the value is true, sinsp events can be printed to the stdout. ([#283](https://github.com/CloudDectective-Harmonycloud/kindling/pull/283))
- Declare the 9500 port in the agent's deployment file ([#282](https://github.com/CloudDectective-Harmonycloud/kindling/pull/282))
### Bug fixes 
- Fix the bug that need_trace_as_span options cannot take effect ([#292](https://github.com/CloudDectective-Harmonycloud/kindling/pull/292))
- Fix connection failure rate data lost when change topology layout in the Grafana plugin. ([#289](https://github.com/CloudDectective-Harmonycloud/kindling/pull/289))
- Fix the bug that the external topologys' metric name is named with `kindling_entity_request` prefix. Change the prefix of these metrics to `kindling_topology_request` ([#287](https://github.com/CloudDectective-Harmonycloud/kindling/pull/287))
- Fix the bug where the table name of SQL is missed if there is no trailing character at the end of the table name. ([#284](https://github.com/CloudDectective-Harmonycloud/kindling/pull/284))

## v0.3.0 - 2022-06-29
### New features
- Add a URL clustering method to reduce the cardinality of the entity metrics. Configuration options are provided to choose which method to use. ([#268](https://github.com/CloudDectective-Harmonycloud/kindling/pull/268)) 
- Display connection failure metrics in the Grafana-plugin ([#255](https://github.com/CloudDectective-Harmonycloud/kindling/pull/255)) 
- Add the metrics that describe how many times the TCP connections have been made ([#234](https://github.com/CloudDectective-Harmonycloud/kindling/pull/234) [#235](https://github.com/CloudDectective-Harmonycloud/kindling/pull/235) [#236](https://github.com/CloudDectective-Harmonycloud/kindling/pull/236) [#237](https://github.com/CloudDectective-Harmonycloud/kindling/pull/237))
- Add a histogram aggregator in defaultAggregator ([#226](https://github.com/CloudDectective-Harmonycloud/kindling/pull/226))
- (Experimental) Support Protocol Dubbo2 ([#184](https://github.com/CloudDectective-Harmonycloud/kindling/pull/184)) 

### Enhancements
- Improve the go project layout ([#273](https://github.com/CloudDectective-Harmonycloud/kindling/pull/273))
- Correct the configurations and disable the `dubbo` protocol parser by default since it is still experimental now. ([#270](https://github.com/CloudDectective-Harmonycloud/kindling/pull/270))
- Implement self-metrics using opentelemetry for cgoreceiver ([#269](https://github.com/CloudDectective-Harmonycloud/kindling/pull/269))
- Use cgo to replace UDS for transferring data from the probe to the collector to improve the performance ([#264](https://github.com/CloudDectective-Harmonycloud/kindling/pull/264))
- Add command labels in tcp connect metrics and span attributes ([#260](https://github.com/CloudDectective-Harmonycloud/kindling/pull/260))
- Use the tcp_close events to generate the srtt metric ([#256](https://github.com/CloudDectective-Harmonycloud/kindling/pull/256))
- Remove the histogram metrics by default to reduce the number of metrics ([#253](https://github.com/CloudDectective-Harmonycloud/kindling/pull/253)) 
- k8sprocessor: use src IP for further searching if the dst IP is a loopback address ([#251](https://github.com/CloudDectective-Harmonycloud/kindling/pull/251))
- docs:update developer links ([#247](https://github.com/CloudDectective-Harmonycloud/kindling/pull/247)) 
- Add some self metrics for agent cpu and memory usage ([#243](https://github.com/CloudDectective-Harmonycloud/kindling/pull/243))
- Export the trace of MySQL request when it contains an error ([#241](https://github.com/CloudDectective-Harmonycloud/kindling/pull/241))
- Block in the application instead of the udsreceiver after running ([#240](https://github.com/CloudDectective-Harmonycloud/kindling/pull/240)) 
- Decouple the logic of dispatching events from receivers ([#232](https://github.com/CloudDectective-Harmonycloud/kindling/pull/232)) 
- Search for k8s metadata using `src_ip` when no containerid found ([#233](https://github.com/CloudDectective-Harmonycloud/kindling/pull/233))
- Record the containers with `hostport` mode and fill the pod information of them in k8sprocessor ([#219](https://github.com/CloudDectective-Harmonycloud/kindling/pull/219))
- Support building Grafana-plugin by using Actions ([#218](https://github.com/CloudDectective-Harmonycloud/kindling/pull/218))
- Improve metrics description doc ([#216](https://github.com/CloudDectective-Harmonycloud/kindling/pull/216)) 
- Update deployment files needed for releasing ([#215](https://github.com/CloudDectective-Harmonycloud/kindling/pull/215)) 

### Bug fixes 
- docs: fix language issues in documents ([#258](https://github.com/CloudDectective-Harmonycloud/kindling/pull/258))
- Fix the bug where the pod information is missed after it is restarted ([#245](https://github.com/CloudDectective-Harmonycloud/kindling/pull/245))
- Grafana-plugin: delete yarn.lock to remove unnecessary dependencies ([#244](https://github.com/CloudDectective-Harmonycloud/kindling/pull/244)) 
- Fix the bug that the container name is incorrect when multiple containers in the pod don't specify ports by setting it empty. ([#238](https://github.com/CloudDectective-Harmonycloud/kindling/pull/238))
- Fix the bug that sometimes the workload kind is `ReplicaSet` ([#230](https://github.com/CloudDectective-Harmonycloud/kindling/pull/230)) 
- Fix "no such file or directory" when using the kubeconfig file. [#225](https://github.com/CloudDectective-Harmonycloud/kindling/pull/225)
- Fix several bugs in the Grafana plugin. ([#220](https://github.com/CloudDectective-Harmonycloud/kindling/pull/220))

## v0.2.0 - 2022-05-07
### Features
- Provide a kindling Prometheus exporter that can support integration with Prometheus easily. See kindling's metrics from the kindling website[http://www.kindling.space:33215/project-1/doc-15/]
- Support network performance, DNS performance, service network maps, and workload performance analysis.
- Support HTTP, MySQL, and REDIS request analysis.
- Provide a Grafana-plugin with four built-in dashboards to support basic analysis features.

