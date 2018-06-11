#pragma once

#include<libtransistor/cpp/types.hpp>

#include<vector>

namespace ilia {

struct SavedDescriptor {
   size_t data_offset;
	size_t size;
};

class Ilia;
class STable;
class Process;

class Pipe {
  public:
   Pipe(Ilia *ilia, STable *s_table, uint32_t id);
   
	bool exists;
	uint32_t pcapng_id;
   std::vector<uint8_t> blob;
	size_t response_offset;
	SavedDescriptor x_descriptors[16];
	SavedDescriptor a_descriptors[16];
	SavedDescriptor b_descriptors[16];
	SavedDescriptor c_descriptors[16];
   Process *process;
   STable *s_table;
   Ilia *ilia;
   uint32_t id;

   void Patch();
};

} // namespace ilia
