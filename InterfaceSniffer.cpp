#include "InterfaceSniffer.hpp"

namespace ilia {

/*

struct nn::sf::cmif::server::CmifServerMessage::vtable {
  nn::Result (*PrepareForProcess)(nn::sf::cmif::server::CmifServerMessage *this, nn::sf::cmif::CmifMessageMetaInfo *info);
  nn::Result (*OverwriteClientProcessId)(nn::sf::cmif::server::CmifServerMessage *this, pid_t *pid);
  nn::Result (*GetBuffers)(nn::sf::cmif::server::CmifServerMessage *this, nn::sf::detail::PointerAndSize *pas);
  nn::Result (*GetInNativeHandles)(nn::sf::cmif::server::CmifServerMessage *this, nn::sf::NativeHandle *handles);
  nn::Result (*GetInObjects)(nn::sf::cmif::server::CmifServerMessage *this, nn::sf::cmif::server::CmifServerObjectInfo *info);
  nn::Result (*BeginPreparingForReply)(nn::sf::cmif::server::CmifServerMessage *this, nn::sf::detail::PointerAndSize *pas);
  nn::Result (*SetBuffers)(nn::sf::cmif::server::CmifServerMessage *this, nn::sf::detail::PointerAndSize *pas);
  nn::Result (*SetOutObjects)(nn::sf::cmif::server::CmifServerMessage *this, nn::sf::cmif::server::CmifServerObjectInfo *info);
  nn::Result (*SetOutNativeHandles)(nn::sf::cmif::server::CmifServerMessage *this, nn::sf::NativeHandle *handles);
  nn::Result (*BeginPreparingForErrorReply)(nn::sf::cmif::server::CmifServerMessage *this, nn::sf::detail::PointerAndSize *pas, uint64_t error_code);
  nn::Result (*EndPreparingForReply)(nn::sf::cmif::server::CmifServerMessage *this);
};
 */

InterfaceSniffer::InterfaceSniffer(Ilia &ilia, Process::STable &s_table) :
	ilia(ilia),
	s_table(s_table),
	s_table_trap(s_table.process, s_table.addr, *this) {
	fprintf(stderr, "made interface sniffer for %s\n", s_table.interface_name.c_str());
}

InterfaceSniffer::MessageContext::MessageContext(
	InterfaceSniffer &sniffer,
	Process::Thread &thread,
	uint64_t object,
	Process::RemotePointer<nn::sf::cmif::server::CmifServerMessage> message,
	Process::RemotePointer<nn::sf::detail::PointerAndSize> pas) :
	CommonContext<InterfaceSniffer>(sniffer, thread),
	message(message),
	vtable(*this, thread.process, (*message).vtable),
	holder(thread, vtable.trap_vtable) {
	fprintf(stderr, "creating message handling context for thread 0x%lx\n", thread.thread_id);
	fprintf(stderr, "poisoning vtable (vt = 0x%lx)...\n", holder.addr);
	message = {holder.addr};
}

InterfaceSniffer::MessageContext::~MessageContext() {
	fprintf(stderr, "leaving message handling context for thread 0x%lx\n", thread.thread_id);
	message = {vtable.real_vtable_addr};
	owner.ilia.destroy_flag = true;
}

InterfaceSniffer::MessageContext::PrepareForProcess::PrepareForProcess(
	MessageContext &ctx,
	Process::Thread &thread,
	uint64_t _this,
	Process::RemotePointer<nn::sf::cmif::CmifMessageMetaInfo> info) :
	CommonContext<MessageContext>(ctx, thread) {
	fprintf(stderr, "entering PrepareForProcess(0x%lx, 0x%lx)\n", _this, info.addr);
}

InterfaceSniffer::MessageContext::PrepareForProcess::~PrepareForProcess() {
	fprintf(stderr, "exiting PrepareForProcess\n");
}

} // namespace ilia
