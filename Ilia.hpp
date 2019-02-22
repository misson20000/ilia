#pragma once

#include<libtransistor/cpp/waiter.hpp>
#include<libtransistor/cpp/ipcserver.hpp>

#include "Process.hpp"
#include "Pipe.hpp"
#include "pcapng.hpp"

#include<map>

namespace ilia {

class Ilia {
  public:
   Ilia();
   
   bool destroy_flag = false;
   pcapng::Writer pcap_writer;
   trn::Waiter event_waiter;
   trn::ipc::server::IPCServer server;
   std::map<uint64_t, Process> processes;
   std::vector<uint8_t> injection_payload;
   uint32_t mitm_func_offsets[8];
   
   trn::ResultCode InterceptAll(std::string interface);
   
  private:
   void ProbeProcesses();
};

} // namespace ilia
