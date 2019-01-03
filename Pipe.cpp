#include "Pipe.hpp"

#include<stdio.h>

#include "Process.hpp"
#include "Ilia.hpp"
#include "pcapng.hpp"

namespace ilia {

Pipe::Pipe(Ilia *ilia, STable *s_table, uint32_t id) : ilia(ilia), s_table(s_table), process(s_table->process), id(id) {
   pcapng::Option options[] = {
      {.code = 2, .length = (uint16_t) (s_table->interface_name.length() + 1), .value = s_table->interface_name.c_str()},
      {.code = 0, .length = 0, .value = NULL}
   };

   pcapng_id = ilia->pcap_writer.WriteIDB(pcapng::LINKTYPE_USER0, 0, options);
}

void Pipe::Patch() {
   if(!s_table->nso->has_injected_payload) {
      s_table->nso->InjectPayload();
   }

   Process::RemoteValue<uint64_t> remote = process->Access<uint64_t>(s_table->addr);
   fprintf(stderr, "patching function pointer...\n");
   remote = s_table->nso->base + ilia->mitm_func_offsets[id];
   fprintf(stderr, "patched function pointer\n");
}

} // namespace ilia
