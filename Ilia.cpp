#include "Ilia.hpp"

#include<libtransistor/cpp/ipc/sm.hpp>

#include<libtransistor/err.h>
#include<libtransistor/ipcserver.h>
#include<libtransistor/ipc/bsd.h>
#include<libtransistor/util.h>
#include<libtransistor/svc.h>

#include<stdio.h>
#include<string.h>
#include<malloc.h>

#include "err.hpp"
#include "pcapng.hpp"
#include "Pipe.hpp"
#include "util.hpp"
#include "IMessageWriter.hpp"
#include "IProxyService.hpp"

int main(int argc, char *argv[]) {
   trn::ResultCode::AssertOk(bsd_init());

	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	struct addrinfo *workstation;
	if(bsd_getaddrinfo("Squash", "5566", &hints, &workstation) != 0) {
		printf("failed gai\n");
      return bsd_result;
	}

	struct sockaddr_in *wk_addr = (struct sockaddr_in*) workstation->ai_addr;
	uint32_t wk_ip = wk_addr->sin_addr.s_addr;
	char *wk_ip_bytes = (char*) &wk_ip;
	printf("connecting to %d.%d.%d.%d:%d\n", wk_ip_bytes[0], wk_ip_bytes[1], wk_ip_bytes[2], wk_ip_bytes[3], ntohs(wk_addr->sin_port));
	
	int socketfd = bsd_socket(workstation->ai_family, workstation->ai_socktype, workstation->ai_protocol);
	printf("opened socket %d\n", socketfd);
	if(socketfd < 0) {
      return bsd_result;
	}
	if(bsd_connect(socketfd, workstation->ai_addr, workstation->ai_addrlen) != 0) {
		printf("failed to connect\n");
      return bsd_result;
	}
	bsd_freeaddrinfo(workstation);

   ilia::Ilia ilia(socketfd);
   trn::ResultCode::AssertOk(ilia.InterceptAll("nns::hosbinder::IHOSBinderDriver").code);
   while(!ilia.destroy_flag) {
      trn::ResultCode::AssertOk(ilia.event_waiter.Wait(3000000000));
   }
   printf("ilia terminating\n");
   
	return 0;
}

namespace ilia {

Ilia::Ilia(int socketfd) :
   pcap_writer(socketfd),
   event_waiter(),
   server(trn::ResultCode::AssertOk(trn::ipc::server::IPCServer::Create(&event_waiter))) {

   server.CreateService("ilia", [this](auto s) {
         printf("something is connecting to ilia\n");
         return new ilia::IProxyService(s, this);
      });

   auto injection_payload_result = util::ReadFile("/squash/injection_payload.bin");
   if(!injection_payload_result) {
      throw trn::ResultError(ILIA_ERR_IO_ERROR);
   }
   this->injection_payload = *injection_payload_result;
   memcpy(mitm_func_offsets, injection_payload.data(), sizeof(mitm_func_offsets));
   
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

   ProbeProcesses();
}

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
         printf("failed to get process handle for %ld: 0x%x\n", pids[i], r.error().code);
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
            printf("patching s_Table(%s) in %ld\n", st.interface_name.c_str(), proc.pid);
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

} // namespace ilia
