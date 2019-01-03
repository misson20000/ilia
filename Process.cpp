#include "Process.hpp"

#include<map>

#include<libtransistor/cpp/svc.hpp>

#include<libtransistor/util.h>
#include<libtransistor/ld/elf.h>

#include "libiberty/include/demangle.h"

#include "Ilia.hpp"
#include "err.hpp"

namespace ilia {

using namespace trn;

struct ModHeader {
   uint32_t magic, dynamic_off, bss_start_off, bss_end_off;
	uint32_t unwind_start_off, unwind_end_off, module_object_off;
};

Process::Process(Ilia *ilia,
                 ipc::client::Object &ldr_dmnt,
                 KProcess proc,
                 uint64_t pid) : ilia(ilia), pid(pid) {
   this->proc = std::make_shared<trn::KProcess>(std::move(proc));

   struct NsoInfo {
      uint64_t addr;
      size_t size;
      union {
         uint8_t build_id[0x20];
         uint64_t build_id_64[4];
      };
   };
   std::vector<NsoInfo> nso_infos(16, {0, 0, 0});
   uint32_t num_nsos;

   ResultCode::AssertOk(
      ldr_dmnt.SendSyncRequest<2>( // GetNsoInfos
         ipc::InRaw<uint64_t>(pid),
         ipc::OutRaw<uint32_t>(num_nsos),
         ipc::Buffer<NsoInfo, 0xA>(nso_infos)));

   nsos.resize(num_nsos, {0});
   
   for(uint32_t i = 0; i < num_nsos; i++) {
      NsoInfo &info = nso_infos[i];
      NSO *nso = &nsos[i];
      *nso = {this, info.addr, info.size};
      uint32_t mod_offset = *Access<uint32_t>(info.addr + 4);
      ModHeader hdr = *Access<ModHeader>(info.addr + mod_offset);

      std::map<int64_t, Elf64_Dyn> dyn_map;
      uint64_t dyn_addr = info.addr + mod_offset + hdr.dynamic_off;
      for(Elf64_Dyn dyn; (dyn = *Access<Elf64_Dyn>(dyn_addr)).d_tag != DT_NULL; dyn_addr+= sizeof(dyn)) {
         dyn_map[dyn.d_tag] = dyn;
      }

      if(dyn_map.find(DT_STRTAB) == dyn_map.end()) {
         fprintf(stderr, "  couldn't find string table\n");
         continue;
      }
      if(dyn_map.find(DT_STRSZ) == dyn_map.end()) {
         fprintf(stderr, "  couldn't find string table size\n");
         continue;
      }

      RemoteValue<char> string_table = Access<char>(info.addr + dyn_map[DT_STRTAB].d_val, dyn_map[DT_STRSZ].d_val);
      if(dyn_map.find(DT_SYMTAB) == dyn_map.end()) {
         fprintf(stderr, "  couldn't find symbol table\n");
         continue;
      }

      if(dyn_map.find(DT_HASH) == dyn_map.end()) {
         fprintf(stderr, "  couldn't find hash table\n");
         continue;
      }

      uint32_t nchain = Access<uint32_t>(info.addr + dyn_map[DT_HASH].d_val, 2)[1];
      RemoteValue<Elf64_Sym> sym_table = Access<Elf64_Sym>(info.addr + dyn_map[DT_SYMTAB].d_val, nchain);
      for(uint32_t i = 0; i < nchain; i++) {
         Elf64_Sym &sym = sym_table[i];
         if(sym.st_name != 0) {
            std::string name = &string_table[sym.st_name];
            size_t pos = name.find("s_Table");
            if(pos == std::string::npos) {
               continue;
            }
            char *demangled = cplus_demangle_v3(name.c_str(), 0);
            name = demangled;
            free(demangled);
            
            static const char prefix[] = "nn::sf::cmif::server::detail::CmifProcessFunctionTableGetter<";
            static const char postfix[] = ", void>::s_Table";
            if(name.compare(0, sizeof(prefix)-1, prefix) == 0 &&
               name.compare(name.length() - (sizeof(postfix) - 1),
                            sizeof(postfix) - 1, postfix) == 0) {
               name = name.substr(sizeof(prefix) - 1, name.length() - sizeof(prefix) + 1 - sizeof(postfix) + 1);
               fprintf(stderr, "  found s_Table: %s\n", name.c_str());
               STable s_table = {this, nso, name, info.addr + sym.st_value, *Access<uint64_t>(info.addr + sym.st_value)};
               fprintf(stderr, "    addr: 0x%lx\n", s_table.addr);
               fprintf(stderr, "    value: 0x%lx\n", s_table.original_value);
               s_tables.push_back(s_table);
            } else {
               fprintf(stderr, "  found non-matching s_Table: %s\n", name.c_str());
            }
         }
      }
   }
}

void Process::NSO::InjectPayload() {
   if(has_injected_payload) {
      return;
   }

   std::vector<uint8_t> &payload = process->ilia->injection_payload;
   RemoteValue<uint8_t> remote = process->Access<uint8_t>(base, payload.size());
   fprintf(stderr, "injecting payload...\n");
   memcpy(&remote[0], payload.data(), payload.size());
   fprintf(stderr, "injected payload\n");
   
   has_injected_payload = true;
}

} // namespace ilia
