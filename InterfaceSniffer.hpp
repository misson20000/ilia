#pragma once

#include "Ilia.hpp"
#include "Process.hpp"
#include "Traps.hpp"

namespace ilia {

class InterfaceSniffer {
 public:
	InterfaceSniffer(Ilia &ilia, Process::STable &s_table);
 private:
	Ilia &ilia;
	Process::STable &s_table;
	
	struct Context {
	};
	
	FunctionPointerTrap<Context>::LambdaInstrument s_table_instrument;
	FunctionPointerTrap<Context> s_table_trap;
};

} // namespace ilia
