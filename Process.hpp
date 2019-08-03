#pragma once

#include<libtransistor/cpp/nx.hpp>

#include<memory>
#include<vector>
#include<list>
#include<deque>
#include<map>

#include "DebugTypes.hpp"

namespace ilia {

class Ilia;
class InterfaceSniffer;

class Process {
 public:
	Process(Ilia &ilia,
					uint64_t pid);
	Process(const Process&) = delete; // disable copy constructor, because we make objects that point to us

	class Thread {
	 public:
		Thread(Process &process, uint64_t id, uint64_t tls, uint64_t entrypoint);
		Process &process;
		const uint64_t thread_id;
		const uint64_t tls;
		const uint64_t entrypoint;

		nx::ThreadContext &GetContext();
		void CommitContext();
		void InvalidateContext();
		
		// for use as map key
		bool operator<(const Thread &rhs) const;
	 private:
		bool is_context_dirty = false;
		bool is_context_valid = false;
		nx::ThreadContext context;
	};
	
	class NSO {
	 public:
		NSO(Process &process, uint64_t base, uint64_t size);
		Process &process;
		const uint64_t base;
		const size_t size;
	};

	class STable {
	 public:
		STable(Process &process, std::string interface_name, uint64_t addr);
		Process &process;
		const std::string interface_name;
		const uint64_t addr;
	};

	class Trap {
	 public:
		Trap(Process &process, std::function<void(Thread&)> cb);
		Trap(const Trap &other) = delete;
		Trap(Trap &&other) = delete;
		virtual ~Trap();

		Trap &operator=(const Trap &other) = delete;
		Trap &operator=(Trap &&other) = delete;
		
		const uint64_t trap_addr;
		void Hit(Thread &thread);
	 protected:
		Process &process;
		std::function<void(Thread&)> cb;
	};
	   
	Ilia &ilia;
	uint64_t pid;
	trn::KDebug debug;
	bool has_attached = false;
	bool has_scanned = false;
	bool pending_begin = false;

	void ScanSTables();
	std::unique_ptr<InterfaceSniffer> Sniff(const char *name);
   std::unique_ptr<InterfaceSniffer> Sniff(std::string name, uint64_t addr);
	void Begin();

	template<typename T>
	class RemotePointer {
	 public:
		RemotePointer(trn::KDebug &debug, uint64_t address) : debug(debug), addr(address) {
		}

		T operator*() {
			T val;
			trn::ResultCode::AssertOk(
				trn::svc::ReadDebugProcessMemory((uint8_t*) &val, debug, addr, sizeof(val)));
			return val;
		}

		T operator=(const T &val) {
			trn::ResultCode::AssertOk(
				trn::svc::WriteDebugProcessMemory(debug, (uint8_t*) &val, addr, sizeof(val)));
			return val;
		}

		T operator[](size_t index) {
			T val;
			trn::ResultCode::AssertOk(
				trn::svc::ReadDebugProcessMemory((uint8_t*) &val, debug, addr + (sizeof(val) * index), sizeof(val)));
			return val;
		}

		const uint64_t addr;
	 private:
		trn::KDebug &debug;
	};
	
	template<typename T>
	T Read(uint64_t addr) {
		return *RemotePointer<T>(debug, addr);
	}

	template<typename T>
	RemotePointer<T> Access(uint64_t addr) {
		return RemotePointer<T>(debug, addr);
	}

	void ReadBytes(std::vector<uint8_t> &buf, uint64_t addr) {
		trn::ResultCode::AssertOk(
			trn::svc::ReadDebugProcessMemory(buf.data(), debug, addr, buf.size()));
	}
	
	void HexDump(std::string header, uint64_t addr, size_t size) {
		std::vector<uint8_t> buf(size);
		ReadBytes(buf, size);

		std::string line;
		size_t position = 0;
		while(position < size) {
			size_t linestart = position;
			line = header;
			
			// hexdump section
			while(position < linestart + 0x10) {
				if(position < size) {
					uint8_t byte = buf[position++];
					line.push_back(nybble2hex(byte >> 4));
					line.push_back(nybble2hex(byte & 15));
					line.push_back(' ');
				} else {
					position++;
					line+= "   ";
				}
				if(position == linestart + 0x8) { line.push_back(' '); }
			}

			line+= " |  ";

			position = linestart;
    
			while(position < linestart + 0x10) {
				if(position < size) {
					uint8_t ch = buf[position++];
					if(ch >= ' ' && ch < 0x7F) {
						line.push_back(ch);
					} else {
						line.push_back('.');
					}
				} else {
					position++;
					line.push_back(' ');
				}
			}

			line.push_back('\n');
			
			fputs(line.c_str(), stderr);
		}
	}
	
 private:
	std::vector<NSO> nsos;
	std::map<std::string, STable> s_tables;
	uint64_t likely_aslr_base;
	
	std::map<uint64_t, Thread> threads;
	std::vector<Trap*> traps;
	std::deque<size_t> trap_free_list;
	static const uint64_t TrapBaseAddress = 0xBAD0000000000000; // near top of address space
	static const size_t TrapSize = 4; // one instruction

	size_t LookupTrap(uint64_t addr);
	uint64_t TrapAddress(size_t index);
	
	std::shared_ptr<trn::WaitHandle> wait_handle;
	
	void HandleEvents();
	uint64_t RegisterTrap(Trap &t); // returns trap address
	void UnregisterTrap(Trap &t);
}; // class Process

} // namespace ilia
