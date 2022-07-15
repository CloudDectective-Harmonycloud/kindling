package constlabels

const (
	NoError = iota
	ConnectFail
	NoResponse
	ProtocolError
)

const (
	Comm            = "comm"
	Pid             = "pid"
	Tid             = "tid"
	Protocol        = "protocol"
	IsError         = "is_error"
	ErrorType       = "error_type"
	IsSlow          = "is_slow"
	IsServer        = "is_server"
	ContainerId     = "container_id"
	SrcNode         = "src_node"
	SrcNodeIp       = "src_node_ip"
	SrcNamespace    = "src_namespace"
	SrcPod          = "src_pod"
	SrcWorkloadName = "src_workload_name"
	SrcWorkloadKind = "src_workload_kind"
	SrcService      = "src_service"
	SrcIp           = "src_ip"
	SrcPort         = "src_port"
	SrcContainerId  = "src_container_id"
	SrcContainer    = "src_container"
	DstNode         = "dst_node"
	DstNodeIp       = "dst_node_ip"
	DstNamespace    = "dst_namespace"
	DstPod          = "dst_pod"
	DstWorkloadName = "dst_workload_name"
	DstWorkloadKind = "dst_workload_kind"
	DstService      = "dst_service"
	DstIp           = "dst_ip"
	DstPort         = "dst_port"
	DnatIp          = "dnat_ip"
	DnatPort        = "dnat_port"
	DstContainerId  = "dst_container_id"
	DstContainer    = "dst_container"
	Node            = "node"
	Namespace       = "namespace"
	WorkloadKind    = "workload_kind"
	WorkloadName    = "workload_name"
	Service         = "service"
	Pod             = "pod"
	Container       = "container"
	Ip              = "ip"
	Port            = "port"

	Errno           = "errno"
	Success         = "success"
	RequestContent  = "request_content"
	ResponseContent = "response_content"
	StatusCode      = "status_code"

	Topic      = "topic"
	Operation  = "operation"
	ConsumerId = "consumer_id"

	RequestDurationStatus   = "request_duration_status"
	RequestReqxferStatus    = "request_reqxfer_status"
	RequestProcessingStatus = "request_processing_status"
	ResponseRspxferStatus   = "response_rspxfer_status"

	ExternalClusterNamespace = "NOT_FOUND_EXTERNAL"
	InternalClusterNamespace = "NOT_FOUND_INTERNAL"

	RequestTotalNs    = "request_total_ns"
	RequestSentNs     = "request_sent_ns"
	WaitingTTfbNs     = "waiting_ttfb_ns"
	ContentDownloadNs = "content_download_ns"
	RequestIoBytes    = "requestio_bytes"
	ResponseIoBytes   = "responseio_bytes"
	Timestamp         = "timestamp"
	IsConvergent      = "is_convergent"

	SpanSrcContainerId   = "src_containerid"
	SpanSrcContainerName = "src_container_name"
	SpanDstContainerId   = "dst_containerid"
	SpanDstContainerName = "dst_container_name"

	SpanHttpMethod          = "http.method"
	SpanHttpEndpoint        = "http.endpoint"
	SpanHttpStatusCode      = "http.status_code"
	SpanHttpTraceId         = "http.trace_id"
	SpanHttpTraceType       = "http.trace_type"
	SpanHttpRequestHeaders  = "http.request_headers"
	SpanHttpRequestBody     = "http.request_body"
	SpanHttpResponseHeaders = "http.response_headers"
	SpanHttpResponseBody    = "http.response_body"

	SpanDnsDomain = "dns.domain"
	SpanDnsRCode  = "dns.rcode"

	SpanMysqlSql       = "mysql.sql"
	SpanMysqlErrorCode = "mysql.error_code"
	SpanMysqlErrorMsg  = "mysql.error_msg"

	PgftMaj = "pgft_maj"
	PgftMin = "pgft_min"
	VmSize  = "vm_size"
	VmRss   = "vm_rss"
	VmSwap  = "vm_swap"
	SpanDubboErrorCode    = "dubbo.error_code"
	SpanDubboRequestBody  = "dubbo.request_body"
	SpanDubboResponseBody = "dubbo.response_body"

	NetWorkAnalyzeMetricGroup = "netAnalyzeMetrics"
)
const (
	STR_EMPTY = ""
)

func IsNamespaceNotFound(namespace string) bool {
	return namespace == ExternalClusterNamespace || namespace == InternalClusterNamespace
}
