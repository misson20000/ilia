#pragma once

#include<libtransistor/cpp/nx.hpp>

#include "Process.hpp"
#include "pcapng.hpp"

#include<map>

namespace ilia {

class Ilia {
  public:
   Ilia();
   
   bool destroy_flag = false;
   pcapng::Writer pcap_writer;
   trn::Waiter event_waiter;
};

} // namespace ilia
