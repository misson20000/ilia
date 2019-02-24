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
#include "util.hpp"

#include "Process.hpp"
#include "InterfaceSniffer.hpp"

int main(int argc, char *argv[]) {
   try {
      ilia::Ilia ilia;

      trn::service::SM sm = trn::ResultCode::AssertOk(trn::service::SM::Initialize());
      trn::ipc::client::Object ldr_dmnt = trn::ResultCode::AssertOk(
         sm.GetService("ldr:dmnt"));
      
      ilia::Process ns(ilia, 0x5b);
      ns.ScanSTables(ldr_dmnt);
      auto a = ns.Sniff("nn::ovln::IReceiverService");
      auto b = ns.Sniff("nn::ovln::IReceiver");
      ns.Begin();
      
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

Ilia::Ilia() :
   pcap_writer(),
   event_waiter() {
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
