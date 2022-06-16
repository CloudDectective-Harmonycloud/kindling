#include <cstdio>
#include <iostream>
#include <cstdlib>
#include "sinsp.h"
#include "src/probe/utils/termination_handler.h"
#include <unistd.h>
#include <sys/un.h>
#include "src/probe/converter/sysdig_converter.h"
#include "src/probe/publisher/publisher.h"
#include "src/probe/converter/kindling_event.pb.h"
#include "driver/driver_config.h"
#include "src/common/base/base.h"
#include "src/probe/catch_sig.h"

#include "src/probe/version.h"
#include <ctime>
#include <string>

DEFINE_int32(sysdig_snaplen, 80, "The len of one sysdig event");
DEFINE_int32(list_batch_size, 100, "The batch size of convert/send list");
DEFINE_int32(list_max_size, INT_MAX, "The max size of convert/send list");
DEFINE_bool(sysdig_output, false, "If true, sysdig will print events log");
DEFINE_int32(sysdig_filter_out_pid_event, -1, "When sysdig_output is true, sysdig will print the exact process's events");
DEFINE_bool(sysdig_bpf, true, "If true, sysdig will use eBPF mode");


void do_inspect(sinsp *inspector, sinsp_evt_formatter *formatter, int pid, publisher* pub) {
    int32_t res;
    sinsp_evt *ev;
    string line;
    converter *sysdigConverter = new sysdig_converter(inspector, FLAGS_list_batch_size, FLAGS_list_max_size);
    while (true) {
        res = inspector->next(&ev);
        if (res == SCAP_TIMEOUT) {
            continue;
        } else if (res != SCAP_SUCCESS) {
            cerr << "res = " << res << endl;
            break;
        }
        if (!inspector->is_debug_enabled() &&
            ev->get_category() & EC_INTERNAL) {
            continue;
        }
        auto threadInfo = ev->get_thread_info();
        if (threadInfo == nullptr) {
            continue;
        }
        // filter out kindling-probe itself and 0
        if (threadInfo->m_ptid == (__int64_t) pid || threadInfo->m_pid == (__int64_t) pid || threadInfo->m_pid == 0) {
            continue;
        }

        // filter out io-related events that do not contain message
        auto category = ev->get_category();
        if (category & EC_IO_BASE) {
            auto pres = ev->get_param_value_raw("res");
            if (pres && *(int64_t *) pres->m_val <= 0) {
                continue;
            }
        }

        pub->consume_sysdig_event(ev, threadInfo->m_pid, sysdigConverter);
        if (FLAGS_sysdig_output && (FLAGS_sysdig_filter_out_pid_event == -1 || FLAGS_sysdig_filter_out_pid_event == threadInfo->m_pid)) {
            if (formatter->tostring(ev, &line)) {
                cout<< line << endl;
            }
        }
    }
}

void get_capture_statistics(sinsp* inspector) {
    LOG(INFO) << "thread for sysdig statistics start";
	scap_stats s;
	while(1) {
		inspector->get_capture_stats(&s);
		LOG(INFO) << "seen by driver: " << s.n_evts;
		if(s.n_drops != 0){
            LOG(INFO) << "Number of dropped events: " << s.n_drops;
		}
		if(s.n_drops_buffer != 0){
            LOG(INFO) << "Number of dropped events caused by full buffer: " << s.n_drops_buffer;
		}
		if(s.n_drops_pf != 0){
            LOG(INFO) << "Number of dropped events caused by invalid memory access: " << s.n_drops_pf;
		}
		if(s.n_drops_bug != 0){
            LOG(INFO) << "Number of dropped events caused by an invalid condition in the kernel instrumentation: " << s.n_drops_bug;
		}
		if(s.n_preemptions != 0){
            LOG(INFO) << "Number of preemptions: " << s.n_preemptions;
		}
		if(s.n_suppressed != 0){
            LOG(INFO) << "Number of events skipped due to the tid being in a set of suppressed tids: " << s.n_suppressed;
		}
		if(s.n_tids_suppressed != 0){
            LOG(INFO) << "Number of threads currently being suppressed: " << s.n_tids_suppressed;
		}
		sleep(10);
	}
}

int main(int argc, char** argv) {
    px::EnvironmentGuard env_guard(&argc, argv);

    int pid = getpid();
    sinsp *inspector = nullptr;
    bool bpf = false;
    string bpf_probe;
    string output_format;
    output_format = "*%evt.num %evt.outputtime %evt.cpu %container.name (%container.id) %proc.name (%thread.tid:%thread.vtid) %evt.dir %evt.type %evt.info";

    LOG(INFO) << "Start kindling probe...";
    LOG(INFO) << "KINDLING_PROBE_"<< _VERSION_ ;
    std::cout << "KINDLING_PROBE_"<< _VERSION_ << std::endl;

    TerminationHandler::InstallSignalHandlers();
    try {
        inspector = new sinsp();
        inspector->set_hostname_and_port_resolution_mode(false);
        sinsp_evt_formatter formatter(inspector, output_format);
        inspector->set_snaplen(FLAGS_sysdig_snaplen);

        inspector->suppress_events_comm("containerd");
        inspector->suppress_events_comm("dockerd");
        inspector->suppress_events_comm("containerd-shim");
        inspector->suppress_events_comm("kindling-collector");
        inspector->suppress_events_comm("sshd");

        const char *probe = scap_get_bpf_probe_from_env();
        if (probe) {
            bpf = true;
            bpf_probe = probe;
        }

        bool open_success = true;

        try {
            inspector->open("");
            inspector->clear_eventmask();
        }
        catch (const sinsp_exception &e) {
            open_success = false;
        }

        //
        // Starting the live capture failed, try to load the driver with
        // modprobe.
        //
        if (!open_success) {
            if (bpf) {
                if (bpf_probe.empty()) {
                    fprintf(stderr, "Unable to locate the BPF probe\n");
                }
            } else {
                if (system("modprobe " PROBE_NAME " > /dev/null 2> /dev/null")) {
                    fprintf(stderr, "Unable to load the driver\n");
                }
            }

            inspector->open("");
        }
        thread catch_signal(sigsetup);
        thread stat(get_capture_statistics, inspector);
        publisher *pub = new publisher(inspector);

        TerminationHandler::set_sinsp(inspector);
        thread inspect(do_inspect, inspector, &formatter, pid, pub);
        pub->start();

        inspector->close();
    }
    catch (const exception &e) {
        fprintf(stderr, "kindling probe init err: %s", e.what());
        return 1;
    }
    delete inspector;
    return 0;
}






