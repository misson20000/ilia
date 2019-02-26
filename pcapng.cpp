#include<algorithm>
#include<iterator>
#include<vector>

#include<libtransistor/cpp/nx.hpp>

#include<malloc.h>
#include<string.h>
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

#include "pcapng.hpp"
#include "err.hpp"

namespace ilia {
namespace pcapng {

Writer::Writer(FILE *file) : file(file) {
}

void Writer::OpenBlock(uint32_t block_type) {
   block_buffer.resize(8, 0);
	((uint32_t*) block_buffer.data())[0] = block_type;
}

void Writer::CommitBlock() {
   block_buffer.insert(block_buffer.end(), 4, 0);
   ((uint32_t*) block_buffer.data())[1] = block_buffer.size();
   *((uint32_t*) (block_buffer.data() + block_buffer.size() - 4)) = block_buffer.size();
   if(fwrite(block_buffer.data(), 1, block_buffer.size(), file) != block_buffer.size()) {
      throw trn::ResultError(ILIA_ERR_IO_ERROR);
   }
   fflush(file);
}

void Writer::AppendToBlock(const uint8_t *data, size_t size) {
   std::copy_n(data, size, std::back_inserter(block_buffer));   
}

void Writer::AppendOptions(Option *options) {
	for(int i = 0; options != NULL && options[i].code != 0; i++) {
		AppendToBlock((uint8_t*) &options[i], 4);
		AppendToBlock((uint8_t*) options[i].value, options[i].length);
		uint32_t zero = 0;
		AppendToBlock((uint8_t*) &zero, ((block_buffer.size() + 3) & ~3) - block_buffer.size());
	}
	Option end = {.code = 0, .length = 0, .value = NULL};
	AppendToBlock((uint8_t*) &end, 4);
}

void Writer::WriteSHB(Option *options) {
	struct {
		uint32_t bom;
		uint16_t major;
		uint16_t minor;
		int64_t length;
	} shb_head;

	OpenBlock(0x0A0D0D0A);
	
	shb_head.bom = 0x1A2B3C4D; // byte order magic
	shb_head.major = 1;
	shb_head.minor = 0;
	shb_head.length = -1;

	AppendToBlock((uint8_t*) &shb_head, sizeof(shb_head));
	AppendOptions(options);
	CommitBlock();

	interface_id = 0; // local to section
}

uint32_t Writer::WriteIDB(uint16_t link_type, uint32_t snap_len, Option *options) {
	struct {
		uint16_t link_type;
		uint16_t reserved;
		uint32_t snap_len;
	} idb_head;

	OpenBlock(0x1);

	idb_head.link_type = link_type;
	idb_head.reserved = 0;
	idb_head.snap_len = snap_len;

	AppendToBlock((uint8_t*) &idb_head, sizeof(idb_head));
	AppendOptions(options);
	CommitBlock();

	return interface_id++;
}

void Writer::WriteEPB(uint32_t if_id, uint64_t timestamp, uint32_t cap_length, uint32_t orig_length, const void *data, Option *options) {
	struct __attribute__((packed)) {
		uint32_t if_id;
		uint32_t ts_hi;
		uint32_t ts_lo;
		uint32_t cap_length;
		uint32_t orig_length;
	} epb_head;

	OpenBlock(0x6);

	epb_head.if_id = if_id;
	epb_head.ts_hi = timestamp >> 32;
	epb_head.ts_lo = timestamp & 0xFFFFFFFF;
	epb_head.cap_length = cap_length;
	epb_head.orig_length = orig_length;

	AppendToBlock((uint8_t*) &epb_head, sizeof(epb_head));
	AppendToBlock((uint8_t*) data, cap_length);
	uint32_t zero = 0;
	AppendToBlock((uint8_t*) &zero, ((block_buffer.size() + 3) & ~3) - block_buffer.size());
	AppendOptions(options);
	CommitBlock();
}

} // namespace pcapng
} // namespace ilia
