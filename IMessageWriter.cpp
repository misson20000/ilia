#include "IMessageWriter.hpp"

#include<libtransistor/err.h>
#include<libtransistor/svc.h>

#include<malloc.h>
#include<string.h>

#include<algorithm>

#include "err.hpp"
#include "pcapng.hpp"
#include "Pipe.hpp"
#include "Process.hpp"
#include "util.hpp"

namespace ilia {

IMessageWriter::IMessageWriter(trn::ipc::server::IPCServer *server, Pipe *pipe, Ilia *ilia) : Object(server), pipe(pipe), ilia(ilia) {
}

trn::ResultCode IMessageWriter::Dispatch(trn::ipc::Message msg, uint32_t rqid) {
   switch(rqid) {
   case 0:
      return trn::ipc::server::RequestHandler<&IMessageWriter::OpenRequest>::Handle(this, msg);
   case 1:
      return trn::ipc::server::RequestHandler<&IMessageWriter::AppendXDescriptor>::Handle(this, msg);
   case 2:
      return trn::ipc::server::RequestHandler<&IMessageWriter::AppendADescriptor>::Handle(this, msg);
   case 3:
      return trn::ipc::server::RequestHandler<&IMessageWriter::OpenResponse>::Handle(this, msg);
   case 4:
      return trn::ipc::server::RequestHandler<&IMessageWriter::AppendBDescriptor>::Handle(this, msg);
   case 5:
      return trn::ipc::server::RequestHandler<&IMessageWriter::AppendCDescriptor>::Handle(this, msg);
   case 6:
      return trn::ipc::server::RequestHandler<&IMessageWriter::CloseMessage>::Handle(this, msg);
   }
	return 1;
}

trn::ResultCode IMessageWriter::OpenRequest(trn::ipc::InRaw<uint64_t> destination, trn::ipc::Buffer<uint8_t, 0x5> message) {
	size_t message_size = 0;
	message_size+= 0x100; // request

	if(message.data == NULL) {
		return trn::ResultCode(LIBTRANSISTOR_ERR_UNSPECIFIED);
	}
	
	ipc_message_t msg;
   {
      auto r = trn::ResultCode::ExpectOk(ipc_unpack((uint32_t*) message.data, &msg));
      if(!r) {
         return r.error();
      }
   }

	uint32_t h;
	ipc_buffer_t a_descriptors[16];
	ipc_buffer_t b_descriptors[16];
	ipc_buffer_t c_descriptors[16];
	ipc_buffer_t x_descriptors[16];
  
	// unpack x descriptors
	h = 0;
	for(uint32_t i = 0; i < msg.num_x_descriptors; i++) {
		uint32_t field = msg.x_descriptors[h++];
		uint64_t addr = 0;
		addr|= (((uint64_t) field >> 6) & 0b111) << 36;
		addr|= (((uint64_t) field >> 12) & 0b1111) << 32;
		addr|= msg.x_descriptors[h++]; // lower 32 bits
		x_descriptors[i].addr = (void*) addr;
		x_descriptors[i].size = field >> 16;
		message_size+= x_descriptors[i].size;
	}

	// unpack a & b descriptors
	h = 0;
	for(uint32_t i = 0; i < msg.num_a_descriptors + msg.num_b_descriptors; i++) {
		ipc_buffer_t *buf = &((i < msg.num_a_descriptors) ? a_descriptors : (b_descriptors - msg.num_a_descriptors))[i];
		uint64_t addr = 0;
		
		buf->size = 0;
		buf->size|= msg.a_descriptors[h++];
		addr|= msg.a_descriptors[h++];

		uint32_t field = msg.a_descriptors[h++];
		uint32_t prot = field & 0b11;
		addr|= (((uint64_t) field >> 2) & 0b111) << 36;
		buf->size|= (((uint64_t) field >> 24) & 0b1111) << 32;
		addr|= (((uint64_t) field >> 28) & 0b1111) << 32;

		buf->addr = (void*) addr;

		uint32_t typemap[] = {0, 1, 0, 2};
		buf->type = typemap[prot] << 6;
		
		message_size+= buf->size;
	}

	// unpack c descriptors
	h = 0;
	uint32_t num_c_descriptors;
	if(msg.c_descriptor_flags == 0) {
		num_c_descriptors = 0;
	} else if(msg.c_descriptor_flags == 1) {
		num_c_descriptors = 0;
	} else if(msg.c_descriptor_flags == 2) {
		num_c_descriptors = 1;
	} else {
		num_c_descriptors = msg.c_descriptor_flags - 2;
	}
	
	for(uint32_t i = 0; i < num_c_descriptors; i++) {
		ipc_buffer_t *buf = &c_descriptors[i];
		uint64_t addr = 0;
		buf->size = 0;

		addr|= msg.c_descriptors[h++];
		uint32_t field = msg.c_descriptors[h++];
		addr|= field & 0xFFFF;
		buf->size|= field >> 16;

		buf->addr = (void*) addr;

		message_size+= buf->size;
	}

	message_size+= 0x100; // response

   pipe->blob.resize(message_size, 0);
   std::copy_n(message.data, message.size, pipe->blob.begin());
   
   size_t offset = 0x100;
	for(int i = 0; i < msg.num_x_descriptors; i++) {
		pipe->x_descriptors[i].data_offset = offset;
		pipe->x_descriptors[i].size = x_descriptors[i].size;
		offset+= x_descriptors[i].size;
	}
	for(int i = 0; i < msg.num_a_descriptors; i++) {
		pipe->a_descriptors[i].data_offset = offset;
		pipe->a_descriptors[i].size = a_descriptors[i].size;
		offset+= a_descriptors[i].size;
	}
	for(int i = 0; i < msg.num_b_descriptors; i++) {
		pipe->b_descriptors[i].data_offset = offset;
		pipe->b_descriptors[i].size = b_descriptors[i].size;
		offset+= b_descriptors[i].size;
	}
	for(int i = 0; i < num_c_descriptors; i++) {
		pipe->c_descriptors[i].data_offset = offset;
		pipe->c_descriptors[i].size = c_descriptors[i].size;
		offset+= c_descriptors[i].size;
	}
	pipe->response_offset = offset;
	offset+= 0x100;
	if(offset > message_size) {
      return trn::ResultCode(0xff);
	}

   return trn::ResultCode(RESULT_OK);
}

trn::ResultCode IMessageWriter::AppendDescriptor(SavedDescriptor *list, uint64_t descriptor_index, trn::ipc::Buffer<uint8_t, 0x5> data) {
	if(data.data == NULL) {
		return trn::ResultCode(LIBTRANSISTOR_ERR_UNSPECIFIED);
	}

	if(descriptor_index < 16) {
      SavedDescriptor &sd = list[descriptor_index];
		if(data.size > sd.size) {
			return 1;
		}
      std::copy_n(data.data, data.size, pipe->blob.begin() + sd.data_offset);
	}
	return RESULT_OK;
}

trn::ResultCode IMessageWriter::AppendXDescriptor(trn::ipc::InRaw<uint64_t> index, trn::ipc::Buffer<uint8_t, 0x5> data) {
   return AppendDescriptor(pipe->x_descriptors, *index, data);
}

trn::ResultCode IMessageWriter::AppendADescriptor(trn::ipc::InRaw<uint64_t> index, trn::ipc::Buffer<uint8_t, 0x5> data) {
   return AppendDescriptor(pipe->a_descriptors, *index, data);
}

trn::ResultCode IMessageWriter::OpenResponse(trn::ipc::InRaw<uint64_t> ignored, trn::ipc::Buffer<uint8_t, 0x5> message) {
	if(message.data == NULL) {
		return trn::ResultCode(LIBTRANSISTOR_ERR_UNSPECIFIED);
	}

   std::copy_n(message.data, message.size, pipe->blob.begin() + pipe->response_offset);
	return RESULT_OK;
}

trn::ResultCode IMessageWriter::AppendBDescriptor(trn::ipc::InRaw<uint64_t> index, trn::ipc::Buffer<uint8_t, 0x5> data) {
   return AppendDescriptor(pipe->b_descriptors, *index, data);
}

trn::ResultCode IMessageWriter::AppendCDescriptor(trn::ipc::InRaw<uint64_t> index, trn::ipc::Buffer<uint8_t, 0x5> data) {
   return AppendDescriptor(pipe->c_descriptors, *index, data);
}

trn::ResultCode IMessageWriter::CloseMessage(trn::ipc::InRaw<uint64_t> ignored, trn::ipc::Buffer<uint8_t, 0x5> also_ignored) {
	ilia->pcap_writer.WriteEPB(pipe->pcapng_id, svcGetSystemTick(), pipe->blob.size(), pipe->blob.size(), pipe->blob.data(), NULL);
   pipe->blob.clear();
	pipe->response_offset = 0;
	memset(pipe->x_descriptors, 0, sizeof(pipe->x_descriptors));
	memset(pipe->a_descriptors, 0, sizeof(pipe->a_descriptors));
	memset(pipe->b_descriptors, 0, sizeof(pipe->b_descriptors));
	memset(pipe->c_descriptors, 0, sizeof(pipe->c_descriptors));
	return RESULT_OK;
}

} // namespace ilia
