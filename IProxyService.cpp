#include "IProxyService.hpp"

#include<libtransistor/ipcserver.h>
#include<libtransistor/err.h>

#include<malloc.h>
#include<string.h>

#include "Pipe.hpp"
#include "Process.hpp"
#include "err.hpp"
#include "util.hpp"
#include "pcapng.hpp"

namespace ilia {

IProxyService::IProxyService(trn::ipc::server::IPCServer *server, Ilia *ilia) : Object(server), ilia(ilia) {
}

trn::ResultCode IProxyService::Dispatch(trn::ipc::Message msg, uint32_t request_id) {
   printf("dispatching %d\n", request_id);
   switch(request_id) {
   case 0:
      return trn::ipc::server::RequestHandler<&IProxyService::CreatePipe>::Handle(this, msg);
   case 1:
      return trn::ipc::server::RequestHandler<&IProxyService::OpenPipeMessageWriter>::Handle(this, msg);
   case 2:
      return trn::ipc::server::RequestHandler<&IProxyService::DebugPoint>::Handle(this, msg);
   case 999:
      return trn::ipc::server::RequestHandler<&IProxyService::DestroyServer>::Handle(this, msg);
   }
   return 1;
}


trn::ResultCode IProxyService::CreatePipe(trn::ipc::Buffer<uint8_t, 0x5> name, trn::ipc::OutRaw<uint32_t> pipe_id) {
	return trn::ResultCode(LIBTRANSISTOR_ERR_UNIMPLEMENTED);
}

trn::ResultCode IProxyService::OpenPipeMessageWriter(trn::ipc::InRaw<uint32_t> pipe_id, trn::ipc::InPid pid, trn::ipc::OutObject<ilia::IMessageWriter> &writer, trn::ipc::OutRaw<uint64_t[2]> offsets) {
   printf("IPS: Opening IMessageWriter for pipe %d on process 0x%lx\n", *pipe_id, pid.value);
   auto pi = ilia->processes.find(pid.value);
   if(pi == ilia->processes.end()) {
      return trn::ResultCode(ILIA_ERR_UNRECOGNIZED_PID);
   }
   Process &proc = pi->second;
   if(*pipe_id >= proc.pipes.size()) {
      return trn::ResultCode(ILIA_ERR_NO_SUCH_PIPE);
   }
	Pipe &pipe = proc.pipes[*pipe_id];
	if(!pipe.exists) {
      return trn::ResultCode(ILIA_ERR_NO_SUCH_PIPE);
	}

	printf("opening message writer for '%s'...\n", pipe.s_table->interface_name.c_str());
   auto writer_result = server->CreateObject<ilia::IMessageWriter>(this, &pipe, ilia);
   if(writer_result) {
      writer.value = *writer_result;
   } else {
      return writer_result.error();
   }

	(*offsets)[0] = pipe.s_table->addr;
	(*offsets)[1] = pipe.s_table->original_value;

	printf("funcptr_offset: 0x%lx\n", pipe.s_table->addr);
	printf("dispatch_offset: 0x%lx\n", pipe.s_table->original_value);
	
	printf("opened message writer\n");
	
	return trn::ResultCode(RESULT_OK);
}

trn::ResultCode IProxyService::DebugPoint(trn::ipc::InRaw<uint64_t> id, trn::ipc::Buffer<uint8_t, 0x5> ignored) {
   printf("hit debug point %ld\n", *id);
   return trn::ResultCode(RESULT_OK);
}

trn::ResultCode IProxyService::DestroyServer() {
   ilia->destroy_flag = true;
   return trn::ResultCode(RESULT_OK);
}

} // namespace ilia
