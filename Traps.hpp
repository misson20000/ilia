#pragma once

#include<libtransistor/cpp/nx.hpp>

#include<tuple>
#include<utility>

#include "err.hpp"

#include "Process.hpp"

using namespace trn;

namespace ilia {

// NOTE: non-reentrant
template<typename Context, typename Arg>
class FunctionTrap {
 public:
	FunctionTrap(Process &process, uint64_t target_addr, Arg &arg) :
		entry_trap(process, [this](Process::Thread &t) { Enter(t); }),
		exit_trap(process, [this](Process::Thread &t) { Exit(t); }),
		process(process),
		cons_param(arg),
		target_addr(target_addr),
		entry_trap_addr(entry_trap.trap_addr) {
	}

	FunctionTrap(std::tuple<Process&, uint64_t, Arg&> &&params) :
		FunctionTrap(
			std::get<0>(params),
			std::get<1>(params),
			std::get<2>(params)) {
	}
	
	void Enter(Process::Thread &t) {
		auto i = contexts.find(t);
		if(i != contexts.end()) {
			throw ResultError(ILIA_ERR_NON_REENTRANT);
		}
		
		nx::ThreadContext &ctx = t.GetContext();
		uint64_t ret = ctx.x[30];
		ctx.x[30] = exit_trap.trap_addr;
		ctx.pc = target_addr;
		contexts.emplace( // this is really dumb
			std::piecewise_construct,
			std::make_tuple(t),
			std::tuple<uint64_t, Process::Thread&, Arg&>(ret, t, cons_param));
	}
	
	void Exit(Process::Thread &t) {
		auto i = contexts.find(t);
		if(i == contexts.end()) {
			throw ResultError(ILIA_ERR_INVALID_TRAP_STATE);
		}
		
		nx::ThreadContext &ctx = t.GetContext();
		ctx.pc = i->second.return_address;
		contexts.erase(i);
	}

	Process &process;
 private:
	Process::Trap entry_trap;
	Process::Trap exit_trap;
 public:
	const uint64_t entry_trap_addr;
	const uint64_t target_addr;
 private:
	Arg &cons_param;
	
	struct InternalContext {
		InternalContext(uint64_t r, Process::Thread &t, Arg &cons_param) :
			return_address(r),
			ctx(cons_param, t) {
		}
		uint64_t return_address;
		Context ctx;
	};
	std::map<Process::Thread, InternalContext> contexts;
};

template<typename Context, typename Arg>
class FunctionPointerTrap : public FunctionTrap<Context, Arg> {
 public:
	FunctionPointerTrap(Process &process, uint64_t ptr, Arg &arg) :
		FunctionTrap<Context, Arg>(process, process.Read<uint64_t>(ptr), arg),
		function_pointer(ptr) {
		process.Access<uint64_t>(ptr) = this->entry_trap_addr;
	}

	~FunctionPointerTrap() {
		this->process.template Access<uint64_t>(function_pointer) = this->target_addr;
	}
 private:
	uint64_t function_pointer;
};

template<typename T, typename... Contexts>
class VTableTrap {
 public:
	using VTableType = std::array<uint64_t, sizeof...(Contexts)>;

	template<std::size_t... I>
	static constexpr std::tuple<FunctionTrap<Contexts, T>...> TrapConstructionHelper(Process &process, const VTableType &real_vtable, T &t, std::index_sequence<I...>) {
		return std::tuple<FunctionTrap<Contexts, T>...>(FunctionTrap<Contexts, T>(process, real_vtable[I], t)...);
	}

	template<std::size_t... I>
	static VTableType TrapVTableHelper(std::tuple<FunctionTrap<Contexts, T>...> &traps, std::index_sequence<I...>) {
		return {(std::get<I>(traps).entry_trap_addr)...};
	}

	VTableTrap(T &t, Process &process, uint64_t real_vtable_addr) :
		VTableTrap(t, process, real_vtable_addr, std::index_sequence_for<Contexts...>()) {
	}

	const T &object;
	const Process &process;
	const uint64_t real_vtable_addr;
	const VTableType real_vtable;
 private: // order is important here
	std::tuple<FunctionTrap<Contexts, T>...> traps;
 public:
	const VTableType trap_vtable;
 private:

	template<std::size_t... I>
	VTableTrap(T &t, Process &process, uint64_t real_vtable_addr, std::index_sequence<I...>) :
		object(t),
		process(process),
		real_vtable_addr(real_vtable_addr),
		real_vtable(process.Read<VTableType>(real_vtable_addr)),
		traps(std::tuple<Process&, uint64_t, T&>(process, real_vtable[I], t)...),
		trap_vtable {(std::get<I>(traps).entry_trap_addr)...} {
	}
};

template<typename T>
class StackHolder {
 public:
	StackHolder(Process::Thread &thread, const T &t) :
		thread(thread),
		addr(thread.GetContext().sp-= sizeof(T)) {
		thread.process.Access<T>(addr) = t;
	}
	~StackHolder() {
		thread.GetContext().sp+= sizeof(T);
	}
	const uint64_t addr;
 private:
	Process::Thread &thread;
};

// just provides some fields to keep track of things that you were going to need to keep track of
// anyway.
template<typename T>
class CommonContext {
 public:
	using Owner = T;
	CommonContext(T &t, Process::Thread &thread) : owner(t), process(thread.process), thread(thread) {
	}
	// for what little remains of my own sanity
	CommonContext(const CommonContext &other) = delete;
	CommonContext(CommonContext &&other) = delete;
	CommonContext &operator=(const CommonContext &other) = delete;
	CommonContext &operator=(CommonContext &&other) = delete;
 protected:
	T &owner;
	Process &process;
	Process::Thread &thread;
};

namespace detail {

template<typename T>
struct UnpackingHelper;

template<>
struct UnpackingHelper<uint64_t> {
	static uint64_t Unpack(Process &process, uint64_t value) {
		return value;
	}
};

template<typename T>
struct UnpackingHelper<Process::RemotePointer<T>> {
	static Process::RemotePointer<T> Unpack(Process &process, uint64_t value) {
		return process.Access<T>(value);
	}
};

} // namespace detail

template<typename Context>
class SmartContext : public CommonContext<typename Context::Owner> {
 public:
	SmartContext(typename Context::Owner &owner, Process::Thread &thread) :
		thread_context(thread.GetContext()),
		CommonContext<typename Context::Owner>(owner, thread),
		context(ConstructionHelper(std::make_index_sequence<std::tuple_size<typename Context::Arguments>::value>())) {
	}
 private:
	nx::ThreadContext &thread_context;
	Context context;
	
	template<std::size_t... I>
	Context ConstructionHelper(std::index_sequence<I...>) {
		return Context(this->owner, this->thread, (detail::UnpackingHelper<typename std::tuple_element<I, typename Context::Arguments>::type>::Unpack(this->process, thread_context.x[I]))...);
	}
};

} // namespace ilia
