#include "InterfaceSniffer.hpp"

namespace ilia {

InterfaceSniffer::InterfaceSniffer(Ilia &ilia, Process::STable &s_table) :
	ilia(ilia),
	s_table(s_table),
	s_table_instrument(
		[this](Process::Thread &t) {
			fprintf(stderr, "hit s_Table for %s\n", this->s_table.interface_name.c_str());
			return Context();
		},
		[this](Process::Thread &t, Context &c) {
			fprintf(stderr, "exiting s_Table for %s\n", this->s_table.interface_name.c_str());
			this->ilia.destroy_flag = true;
		}),
	s_table_trap(s_table.process, s_table.addr, s_table_instrument) {
	fprintf(stderr, "made interface sniffer for %s\n", s_table.interface_name.c_str());
}

} // namespace ilia
