#pragma once

#include<libtransistor/cpp/nx.hpp>

#include "Process.hpp"
#include "pcapng.hpp"

#include<map>

namespace ilia {

class InterfaceSniffer;

class Ilia {
  public:
   Ilia(FILE *pcap);
   
   bool destroy_flag = false;
   pcapng::Writer pcap_writer;
   trn::Waiter event_waiter;

   trn::service::SM sm;
   trn::ipc::client::Object ldr_dmnt;
   trn::ipc::client::Object pm_dmnt;

   std::map<uint64_t, Process> processes;
   std::vector<std::unique_ptr<InterfaceSniffer>> sniffers;
};

} // namespace ilia
