#pragma once

#include<libtransistor/cpp/types.hpp>
#include<libtransistor/cpp/ipcserver.hpp>

#include "Ilia.hpp"
#include "Pipe.hpp"
#include "pcapng.hpp"

namespace ilia {

class IMessageWriter : public trn::ipc::server::Object {
  public:
   IMessageWriter(trn::ipc::server::IPCServer *server, Pipe *pipe, Ilia *ilia);
   
   virtual trn::ResultCode Dispatch(trn::ipc::Message msg, uint32_t request_id);

   trn::ResultCode OpenRequest(trn::ipc::InRaw<uint64_t> destination, trn::ipc::Buffer<uint8_t, 0x5> raw_message);
   trn::ResultCode AppendXDescriptor(trn::ipc::InRaw<uint64_t> index, trn::ipc::Buffer<uint8_t, 0x5> data);
   trn::ResultCode AppendADescriptor(trn::ipc::InRaw<uint64_t> index, trn::ipc::Buffer<uint8_t, 0x5> data);
   trn::ResultCode OpenResponse(trn::ipc::InRaw<uint64_t> ignored, trn::ipc::Buffer<uint8_t, 0x5> raw_message);
   trn::ResultCode AppendBDescriptor(trn::ipc::InRaw<uint64_t> index, trn::ipc::Buffer<uint8_t, 0x5> data);
   trn::ResultCode AppendCDescriptor(trn::ipc::InRaw<uint64_t> index, trn::ipc::Buffer<uint8_t, 0x5> data);
   trn::ResultCode CloseMessage(trn::ipc::InRaw<uint64_t> ignored, trn::ipc::Buffer<uint8_t, 0x5> ignored2);
  private:
   Pipe *pipe;
   Ilia *ilia;
   
   trn::ResultCode AppendDescriptor(SavedDescriptor *list, uint64_t index, trn::ipc::Buffer<uint8_t, 0x5> data);
};

}
