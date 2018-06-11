#pragma once

#include<libtransistor/cpp/ipcserver.hpp>

#include "IMessageWriter.hpp"

namespace ilia {

class IProxyService : public trn::ipc::server::Object {
  public:
   IProxyService(trn::ipc::server::IPCServer *server, Ilia *ilia);

   virtual trn::ResultCode Dispatch(trn::ipc::Message msg, uint32_t request_id);

   trn::ResultCode CreatePipe(trn::ipc::Buffer<uint8_t, 0x5> name, trn::ipc::OutRaw<uint32_t> pipe_id);
   trn::ResultCode OpenPipeMessageWriter(trn::ipc::InRaw<uint32_t> pipe_id, trn::ipc::InPid pid, trn::ipc::OutObject<ilia::IMessageWriter> &writer, trn::ipc::OutRaw<uint64_t[2]> offsets);
   trn::ResultCode DebugPoint(trn::ipc::InRaw<uint64_t> id, trn::ipc::Buffer<uint8_t, 0x5> ignored);
   trn::ResultCode DestroyServer();
  private:
   Ilia *ilia;
};

} // namespace ilia
