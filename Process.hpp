#pragma once

#include<libtransistor/cpp/types.hpp>
#include<libtransistor/cpp/ipcclient.hpp>
#include<libtransistor/cpp/svc.hpp>

#include<libtransistor/util.h>

#include<memory>
#include<vector>
#include<list>

#include "Pipe.hpp"

namespace ilia {

class Process;
class STable;

class Process {
  public:
   Process(Ilia *ilia,
           trn::ipc::client::Object &ldr_dmnt,
           trn::KProcess proc,
           uint64_t pid);
   Process(const Process&) = delete; // disable copy constructor, because we make objects that point to us
   
   template<typename T>
   class RemoteValue {
     public:
      RemoteValue(std::shared_ptr<trn::svc::MemoryMapping> map, uint64_t offset) : map(map), offset(offset) {
      }

      T operator*() {
         return *((T*) (map->Base() + offset));
      }

      T operator=(T val) {
         return *((T*) (map->Base() + offset)) = val;
      }

      T &operator[](size_t index) {
         return *(((T*) (map->Base() + offset)) + index);
      }
      
     private:
      std::shared_ptr<trn::svc::MemoryMapping> map;
      uint64_t offset;
   };

   class NSO {
     public:
      Process *process;
      uint64_t base;
      size_t size;
      bool has_injected_payload = false;
      
      void InjectPayload();
   };
      
   uint64_t pid;
   std::shared_ptr<trn::KProcess> proc;
   std::vector<NSO> nsos;
   std::list<STable> s_tables;
   std::vector<Pipe> pipes;
   Ilia *ilia;
   
   template<typename T> RemoteValue<T> Access(uint64_t addr, size_t count) {
      uint64_t aligned_addr = addr & ~0xfff;
      uint64_t end = addr + (sizeof(T) * count);
      uint64_t size = end - aligned_addr;
      uint64_t aligned_size = (size + 0xfff) & ~0xfff;
      auto r = trn::svc::MapProcessMemory(this->proc, aligned_addr, aligned_size);
      while(!r && r.error().code == 0xdc01) {
         printf("looping on 0xdc01\n");
         svcSleepThread(100000);
         r = trn::svc::MapProcessMemory(this->proc, aligned_addr, aligned_size);
      }
      if(!r) {
         throw new trn::ResultError(r.error());
      }
      return RemoteValue<T>(*r,
                            addr - aligned_addr);
   }
   template<typename T> RemoteValue<T> Access(uint64_t addr) { return Access<T>(addr, 1); }

   void HexDump(uint64_t addr, size_t size) {
      RemoteValue<uint8_t> buf = Access<uint8_t>(addr, size);
      hexdump(&buf[0], size);
   }
};

class STable {
  public:
   Process *process;
   Process::NSO *nso;
   std::string interface_name;
   uint64_t addr;
   uint64_t original_value;
};


} // namespace ilia
