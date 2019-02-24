#pragma once

#include<libtransistor/cpp/nx.hpp>

#include "err.hpp"

#include "Process.hpp"

using namespace trn;

namespace ilia {

// NOTE: non-reentrant
template<typename Context>
class FunctionPointerTrap {
 public:
	class Instrument;
   
	FunctionPointerTrap(Process &process, uint64_t ptr, Instrument &instrument) :
		entry_trap(process, [this](Process::Thread &t) { Enter(t); }),
		exit_trap(process, [this](Process::Thread &t) { Exit(t); }),
		process(process),
		function_pointer(ptr),
		instrument(instrument),
		original_value(process.Read<uint64_t>(ptr)) {
		fprintf(
			stderr, "installing function pointer trap ([0x%lx] 0x%lx -> 0x%lx)\n",
			ptr, original_value, entry_trap.trap_addr);
		process.Access<uint64_t>(ptr) = entry_trap.trap_addr;
	}

	~FunctionPointerTrap() {
		fprintf(
			stderr, "uninstalling function pointer trap ([0x%lx] 0x%lx -> 0x%lx)\n",
			function_pointer, entry_trap.trap_addr, original_value);
		process.Access<uint64_t>(function_pointer) = original_value;
	}

	struct Instrument {
		virtual Context Enter(Process::Thread &t) = 0;
		virtual void Exit(Process::Thread &t, Context &c) = 0;
	};

	class LambdaInstrument : public Instrument {
	 public:
		LambdaInstrument(
			std::function<Context(Process::Thread&)> enter,
			std::function<void(Process::Thread&, Context&)> exit) : enter(enter), exit(exit) {
		}

		virtual Context Enter(Process::Thread &t) {
			return enter(t);
		}

		virtual void Exit(Process::Thread &t, Context &c) {
			return exit(t, c);
		}
	 private:
		std::function<Context(Process::Thread&)> enter;
		std::function<void(Process::Thread&, Context&)> exit;
	};
	
	void Enter(Process::Thread &t) {
		fprintf(stderr, "entering function pointer trap\n");
		auto i = contexts.find(t);
		if(i != contexts.end()) {
			throw ResultError(ILIA_ERR_NON_REENTRANT);
		}
		
		nx::ThreadContext ctx = t.GetContext();
		uint64_t ret = ctx.x[30];
		ctx.x[30] = exit_trap.trap_addr;
		ctx.pc = original_value;
		fprintf(stderr, "  return to: 0x%lx, trapping x30 to 0x%lx...\n", ret, exit_trap.trap_addr);
		fprintf(stderr, "  warping pc to original function 0x%lx...\n", original_value);
		t.SetContext(ctx);
		contexts.emplace(t, InternalContext(ret, instrument.Enter(t)));
	}
	
	void Exit(Process::Thread &t) {
		fprintf(stderr, "exiting function pointer trap\n");
		auto i = contexts.find(t);
		if(i == contexts.end()) {
			throw ResultError(ILIA_ERR_INVALID_TRAP_STATE);
		}
		instrument.Exit(t, i->second.ctx);
		
		nx::ThreadContext ctx = t.GetContext();
		ctx.pc = i->second.return_address;
		fprintf(stderr, "  restoring pc to saved x30: 0x%lx...\n", i->second.return_address);
		t.SetContext(ctx);
		contexts.erase(i);
	}
	
 private:
	Process &process;
	Process::Trap entry_trap;
	Process::Trap exit_trap;
	uint64_t function_pointer;
	uint64_t original_value;
	Instrument &instrument;
	struct InternalContext {
		InternalContext(uint64_t r, Context ctx) : return_address(r), ctx(ctx) {
		}
		uint64_t return_address;
		Context ctx;
	};
	std::map<Process::Thread, InternalContext> contexts;
};

} // namespace ilia
