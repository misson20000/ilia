#include "Process.hpp"

#include<stdio.h>

#include<map>

#include<libtransistor/cpp/nx.hpp>

#include "libiberty/include/demangle.h"

#include "err.hpp"

#include "Ilia.hpp"
#include "DebugTypes.hpp"
#include "InterfaceSniffer.hpp"

namespace ilia {

using namespace trn;

struct ModHeader {
	uint32_t magic, dynamic_off, bss_start_off, bss_end_off;
	uint32_t unwind_start_off, unwind_end_off, module_object_off;
};

Process::Process(
	Ilia &ilia,
	uint64_t pid) :
	ilia(ilia), pid(pid),
	debug(ResultCode::AssertOk(svc::DebugActiveProcess(pid))),
	wait_handle(
		ilia.event_waiter.Add(
			debug,
			[this]() -> bool { HandleEvents(); return true; })) {
}

Process::Thread::Thread(Process &process, uint64_t id, uint64_t tls, uint64_t entrypoint) :
	process(process),
	thread_id(id),
	tls(tls),
	entrypoint(entrypoint) {
}

nx::ThreadContext &Process::Thread::GetContext() {
	if(!is_context_valid) {
		*((thread_context_t*) (&context)) = ResultCode::AssertOk(
			svc::GetDebugThreadContext(process.debug, thread_id, 15));
		is_context_valid = true;
	}
	is_context_dirty = true;
	return context;
}

void Process::Thread::CommitContext() {
	if(is_context_dirty) {
		ResultCode::AssertOk(
			svc::SetDebugThreadContext(process.debug, thread_id, (thread_context_t*) &context, 3));
		is_context_dirty = false;
	}
}

void Process::Thread::InvalidateContext() {
	is_context_valid = false;
}

bool Process::Thread::operator<(const Thread &rhs) const {
	return thread_id < rhs.thread_id;
}

Process::NSO::NSO(Process &process, uint64_t base, uint64_t size) :
	process(process),
	base(base),
	size(size) {
}

Process::STable::STable(Process &process, std::string interface_name, uint64_t addr) :
	process(process),
	interface_name(interface_name),
	addr(addr) {
}

Process::Trap::Trap(Process &process, std::function<void(Thread&)> cb) :
	trap_addr(process.RegisterTrap(*this)),
	process(process),
	cb(cb) {
}

Process::Trap::~Trap() {
	process.UnregisterTrap(*this);
}

void Process::Trap::Hit(Thread &t) {
	cb(t);
}

std::unique_ptr<InterfaceSniffer> Process::Sniff(const char *name) {
   if(!has_scanned) {
      ScanSTables();
   }
	auto i = s_tables.find(std::string(name));
	if(i == s_tables.end()) {
		throw ResultError(ILIA_ERR_NO_SUCH_S_TABLE);
	}

	return std::make_unique<InterfaceSniffer>(ilia, i->second);
}

std::unique_ptr<InterfaceSniffer> Process::Sniff(std::string name, uint64_t offset) {
   if(!has_scanned) {
      ScanSTables();
   }
   auto i = s_tables.emplace(name, STable(*this, name, likely_aslr_base + offset)).first;
   return std::make_unique<InterfaceSniffer>(ilia, i->second);
}

void Process::HandleEvents() {
	trn::Result<debug_event_info_t> r;
	
	while((r = svc::GetDebugEvent(debug))) {
		nx::DebugEvent event = {};
		static_assert(sizeof(event) == sizeof(*r));
		memcpy((void*) &event, (void*) &(*r), sizeof(event));
		
		switch(event.event_type) {
		case nx::DebugEvent::EventType::AttachProcess: {
			if(has_attached) {
				throw ResultError(ILIA_ERR_INVALID_PROCESS_STATE);
			}
			fprintf(stderr, "attached process '%s'\n", event.attach_process.process_name);
			has_attached = true;
			break; }
		case nx::DebugEvent::EventType::AttachThread: {
			if(!has_attached) {
				throw ResultError(ILIA_ERR_INVALID_PROCESS_STATE);
			}
			auto i = threads.find(event.attach_thread.thread_id);
			if(i != threads.end()) {
				throw ResultError(ILIA_ERR_INVALID_THREAD_STATE);
			}
			threads.emplace(
				event.attach_thread.thread_id, Thread(
					*this,
					event.attach_thread.thread_id,
					event.attach_thread.tls_pointer,
					event.attach_thread.entrypoint));
			fprintf(stderr, "attached thread 0x%lx\n", event.attach_thread.thread_id);
			break; }
		case nx::DebugEvent::EventType::ExitProcess: {
			fprintf(stderr, "ERROR: exited process?\n");
			break; }
		case nx::DebugEvent::EventType::ExitThread: {
			threads.erase(event.thread_id);
			fprintf(stderr, "exited thread 0x%lx\n", event.thread_id);
			break; }
		case nx::DebugEvent::EventType::Exception: {
			switch(event.exception.exception_type) {
			case nx::DebugEvent::ExceptionType::InstructionAbort: {
				uint64_t far = event.exception.fault_register;
				auto i = threads.find(event.thread_id);
				if(i == threads.end()) {
					fprintf(stderr, "ERROR: no such thread 0x%lx\n", event.thread_id);
					break;
				}
				size_t index = LookupTrap(far);
				if(traps[index] == nullptr) {
					fprintf(stderr, "ERROR: no such trap 0x%lx\n", index);
				} else {
					traps[index]->Hit(i->second);
				}
				break; }
			case nx::DebugEvent::ExceptionType::DebuggerAttached: {
				fprintf(stderr, "got debugger attachment exception\n");
				break; }
			default:
				fprintf(stderr, "ERROR: unhandled exception\n");
				return;
			}
			break; }
		default:
			fprintf(stderr, "ERROR: unknown debug event?\n");
			return;
		}
	}
	
	if(r.error().code != 0x8c01) { // no events left
		throw r.error();
	}

	for(auto &i : threads) {
		i.second.CommitContext();
		i.second.InvalidateContext();
	}
	ResultCode::AssertOk(
		svc::ContinueDebugEvent(debug, 7, nullptr, 0));
}

uint64_t Process::RegisterTrap(Trap &t) {
	if(!trap_free_list.empty()) {
		size_t index = trap_free_list.front();
		trap_free_list.pop_front();
		traps[index] = &t;
		return TrapAddress(index);
	} else {
		uint64_t addr = TrapAddress(traps.size());
		traps.push_back(&t);
		return addr;
	}
}

void Process::UnregisterTrap(Trap &t) {
	size_t index = LookupTrap(t.trap_addr);
	if(traps[index] != &t) {
		throw ResultError(ILIA_ERR_INVALID_TRAP);
	}
	traps[index] = nullptr;
	trap_free_list.push_back(index);
}

size_t Process::LookupTrap(uint64_t addr) {
	if(addr < TrapBaseAddress) {
		throw ResultError(ILIA_ERR_INVALID_TRAP);
	}
	if(addr >= TrapBaseAddress + (traps.size() * TrapSize)) {
		throw ResultError(ILIA_ERR_INVALID_TRAP);
	}
	return (addr - TrapBaseAddress) / TrapSize;
}

uint64_t Process::TrapAddress(size_t index) {
	return TrapBaseAddress + (index * TrapSize);
}

void Process::ScanSTables() {
	struct NsoInfo {
		union {
			uint8_t build_id[0x20];
			uint64_t build_id_64[4];
		};
		uint64_t addr;
		size_t size;
	};
	std::vector<NsoInfo> nso_infos(16, {0, 0, 0});
	uint32_t num_nsos;

   if(pid >= 0x50) {
		 ResultCode::AssertOk(
			 ilia.ldr_dmnt.SendSyncRequest<2>( // GetNsoInfos
				 ipc::InRaw<uint64_t>(pid),
				 ipc::OutRaw<uint32_t>(num_nsos),
				 ipc::Buffer<NsoInfo, 0xA>(nso_infos)));
	 } else {
		 uint64_t addr = 0;
		 memory_info_t mi;
		 while((mi = std::get<0>(ResultCode::AssertOk(svc::QueryDebugProcessMemory(debug, addr)))).memory_type != 3) {
			 if((uint64_t) mi.base_addr + mi.size < addr) {
				 fprintf(stderr, "giving up on finding module...\n");
				 return;
			 }
			 addr = (uint64_t) mi.base_addr + mi.size;
		 }

		 fprintf(stderr, "found module at 0x%lx\n", addr);
		 
		 nso_infos[0] = {.addr = addr};
		 num_nsos = 1;
	 }

	 likely_aslr_base = nso_infos[0].addr;

	for(uint32_t i = 0; i < num_nsos; i++) {
		NsoInfo &info = nso_infos[i];
		NSO &nso = nsos.emplace_back(*this, info.addr, info.size);
		
		uint32_t mod_offset = Read<uint32_t>(info.addr + 4);
		ModHeader hdr = Read<ModHeader>(info.addr + mod_offset);

		std::map<int64_t, Elf64_Dyn> dyn_map;
		uint64_t dyn_addr = info.addr + mod_offset + hdr.dynamic_off;
		for(Elf64_Dyn dyn; (dyn = Read<Elf64_Dyn>(dyn_addr)).d_tag != DT_NULL; dyn_addr+= sizeof(dyn)) {
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

		RemotePointer<char> string_table = RemotePointer<char>(debug, info.addr + dyn_map[DT_STRTAB].d_val);
		if(dyn_map.find(DT_SYMTAB) == dyn_map.end()) {
			fprintf(stderr, "  couldn't find symbol table\n");
			continue;
		}

		if(dyn_map.find(DT_HASH) == dyn_map.end()) {
			fprintf(stderr, "  couldn't find hash table\n");
			continue;
		}

		uint32_t nchain = Access<uint32_t>(info.addr + dyn_map[DT_HASH].d_val)[1];
		RemotePointer<Elf64_Sym> sym_table = Access<Elf64_Sym>(info.addr + dyn_map[DT_SYMTAB].d_val);
		for(uint32_t i = 0; i < nchain; i++) {
			Elf64_Sym sym = sym_table[i];
			if(sym.st_name != 0) {
				std::string name;
				size_t p = sym.st_name;
				char c;
				while((c = string_table[p++])) {
					name.push_back(c);
				}
				
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
					s_tables.emplace(name, STable(*this, name, info.addr + sym.st_value));
				} else {
					fprintf(stderr, "  found non-matching s_Table: %s\n", name.c_str());
				}
			}
		}
	}

   has_scanned = true;
}

} // namespace ilia
