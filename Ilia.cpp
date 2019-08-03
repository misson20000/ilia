#include "Ilia.hpp"

#include<libtransistor/cpp/ipc/sm.hpp>

#include<libtransistor/err.h>
#include<libtransistor/ipcserver.h>
#include<libtransistor/ipc/bsd.h>
#include<libtransistor/util.h>
#include<libtransistor/svc.h>

#include<unistd.h>
#include<stdio.h>
#include<string.h>
#include<malloc.h>
#include<fcntl.h>

#include "ini.h"

#include "err.hpp"
#include "pcapng.hpp"
#include "util.hpp"

#include "Process.hpp"
#include "InterfaceSniffer.hpp"

static int IniSectionHandler(void *user, const char *section, void **section_context) {
	ilia::Ilia &ilia = *(ilia::Ilia*) user;

	std::string buf = section;
	std::string::size_type i = buf.find(' ');
	if(i == std::string::npos) {
		fprintf(stderr, "didn't find space\n");
		return 0;
	}

	uint64_t pid;
	if(buf.substr(0, i) == "title") {
		size_t index;
		uint64_t tid = std::stoull(buf.substr(i+1), &index, 16);
		fprintf(stderr, "looking up tid 0x%lx\n", tid);
		if(index != buf.size() - i - 1) {
			return 0;
		}
		if(env_get_kernel_version() >= KERNEL_VERSION_500) {
			ResultCode::AssertOk(
				ilia.pm_dmnt.SendSyncRequest<2>(
					ipc::InRaw<uint64_t>(tid),
					ipc::OutRaw<uint64_t>(pid)));
		} else {
			ResultCode::AssertOk(
				ilia.pm_dmnt.SendSyncRequest<3>(
					ipc::InRaw<uint64_t>(tid),
					ipc::OutRaw<uint64_t>(pid)));
		}
	} else if(buf.substr(0, i) == "pid") {
		size_t index;
		pid = std::stoull(buf.substr(i+1), &index, 0);
		if(index != buf.size() - i - 1) {
			return 0;
		}
	} else {
		fprintf(stderr, "unrecognized: '%s'\n",buf.substr(0, i).c_str());
		return 0;
	}

	fprintf(stderr, "attaching to process 0x%lx\n", pid);
   
	auto p = ilia.processes.find(pid);
	if(p == ilia.processes.end()) {
		p = ilia.processes.emplace(
			std::piecewise_construct,
			std::make_tuple(pid),
			std::tuple<ilia::Ilia&, uint64_t>(ilia, pid)).first;
	}

	*section_context = (void*) &p->second;
	return 1;
}

static int IniValueHandler(void *user, void *section_context, const char *name, const char *value) {
	if(section_context == nullptr) {
		return 0;
	}
	
	ilia::Ilia &ilia = *(ilia::Ilia*) user;
	ilia::Process &proc = *(ilia::Process*) section_context;

	if(strcmp(value, "auto") == 0) {
		ilia.sniffers.emplace_back(std::move(proc.Sniff(name)));
	} else {
		size_t offset = std::stoull(value, nullptr, 0);
		fprintf(stderr, "attaching to manual '%s' = 0x%lx (\"%s\")\n", name, offset, value);
		ilia.sniffers.emplace_back(std::move(proc.Sniff(name, offset)));
	}
	
	return 1;
}

class Time {
 public:
	Time() {
		ResultCode::AssertOk(time_init());
	}
	~Time() {
		time_finalize();
	}
	uint64_t GetCurrentTime() {
		uint64_t t;
		ResultCode::AssertOk(time_system_clock_get_current_time(time_system_clock_local, &t));
		return t;
	}
};

int main(int argc, char *argv[]) {
	try {
		Time t;
		char fname[301];
		time_t time = t.GetCurrentTime();
		strftime(fname, sizeof(fname)-1, "/sd/ilia_%F_%H-%M-%S.pcapng", gmtime(&time));
		fprintf(stderr, "opening '%s'...\n", fname);
		FILE *log = fopen(fname, "wb");
		
		ilia::Ilia ilia(log);

		FILE *f = fopen("/sd/ilia.ini", "r");
		if(!f) {
			fprintf(stderr, "could not open configuration\n");
			return 1;
		}

		int error = ini_parse_file(f, &IniValueHandler, &IniSectionHandler, &ilia);
		if(error != 0) {
			fprintf(stderr, "ini error on line %d\n", error);
			return 1;
		}
		
		while(!ilia.destroy_flag) {
			trn::ResultCode::AssertOk(ilia.event_waiter.Wait(3000000000));
		}
		fprintf(stderr, "ilia terminating\n");
   
		return 0;
	} catch(trn::ResultError &e) {
		fprintf(stderr, "caught ResultError: 0x%x\n", e.code.code);
		return e.code.code;
	}
}

namespace ilia {

Ilia::Ilia(FILE *pcap) :
	pcap_writer(pcap),
	event_waiter(),
	sm(trn::ResultCode::AssertOk(trn::service::SM::Initialize())),
	ldr_dmnt(trn::ResultCode::AssertOk(sm.GetService("ldr:dmnt"))),
	pm_dmnt(trn::ResultCode::AssertOk(sm.GetService("pm:dmnt"))) {
	static const char shb_hardware[] = "Nintendo Switch";
	static const char shb_os[] = "Horizon";
	static const char shb_userappl[] = "ilia";
	pcapng::Option shb_options[] = {
		{.code = pcapng::SHB_HARDWARE, .length = sizeof(shb_hardware), .value = shb_hardware},
		{.code = pcapng::SHB_OS, .length = sizeof(shb_os), .value = shb_os},
		{.code = pcapng::SHB_USERAPPL, .length = sizeof(shb_userappl), .value = shb_userappl},
		{.code = 0, .length = 0, .value = 0}
	};
	pcap_writer.WriteSHB(shb_options);
}

/*
	void Ilia::ProbeProcesses() {
	uint64_t pids[256];
	uint32_t num_pids;
	trn::ResultCode::AssertOk(svcGetProcessList(&num_pids, pids, ARRAY_LENGTH(pids)));

	trn::service::SM sm = trn::ResultCode::AssertOk(trn::service::SM::Initialize());
	trn::ipc::client::Object pm_dmnt = trn::ResultCode::AssertOk(
	sm.GetService("pm:dmnt"));
	trn::ipc::client::Object ldr_dmnt = trn::ResultCode::AssertOk(
	sm.GetService("ldr:dmnt"));
   
	for(uint32_t i = 0; i < num_pids; i++) {
	handle_t proc_handle;
	auto r = pm_dmnt.SendSyncRequest<65000>( // Atmosphere-GetProcessHandle
	trn::ipc::InRaw<uint64_t>(pids[i]),
	trn::ipc::OutHandle<handle_t, trn::ipc::copy>(proc_handle));
	if(!r) {
	fprintf(stderr, "failed to get process handle for %ld: 0x%x\n", pids[i], r.error().code);
	continue;
	}
   
	processes.try_emplace(pids[i], this, ldr_dmnt, std::move(trn::KProcess(proc_handle)), pids[i]);
	}
	}

	trn::ResultCode Ilia::InterceptAll(std::string interface_name) {
	for(auto &kv : processes) {
	auto &proc = kv.second;
	for(auto &st : proc.s_tables) {
	if(st.interface_name == interface_name) {
	fprintf(stderr, "patching s_Table(%s) in %ld\n", st.interface_name.c_str(), proc.pid);
	if(proc.pipes.size() >= 16) {
	return trn::ResultCode(ILIA_ERR_TOO_MANY_PIPES);
	}
	Pipe pipe(this, &st, proc.pipes.size());
	proc.pipes.push_back(pipe);
	pipe.Patch();
	}
	}
	}
   
	return trn::ResultCode(RESULT_OK);
	}
*/

} // namespace ilia
