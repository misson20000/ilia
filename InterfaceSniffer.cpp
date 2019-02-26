#include "InterfaceSniffer.hpp"

#include<experimental/array>

#include "Buffer.hpp"

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
	interface_id(
		ilia.pcap_writer.WriteIDB(
			pcapng::LINKTYPE_USER1, 0,
			std::experimental::make_array(
				pcapng::Option {.code = 2, .length = (uint16_t) (s_table.interface_name.length() + 1), .value = s_table.interface_name.c_str()},
				pcapng::Option {.code = 0, .length = 0, .value = nullptr}
				).data())),
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
	rq_pas(*pas),
	rq_data(rq_pas.size),
	vtable(*this, thread.process, (*message).vtable),
	holder(thread, vtable.trap_vtable) {
	//fprintf(stderr, "entering message handling context for thread 0x%lx\n", thread.thread_id);
	process.ReadBytes(rq_data, rq_pas.pointer);
	message = {holder.addr}; // poison vtable
}

enum class ChunkType : uint8_t {
	RequestPas,
	RequestData,
	MetaInfo,
	ResponsePas,
	ResponseData,
	ResultCode,
	Buffers,
};

static void AddChunk(util::Buffer &message, ChunkType type, util::Buffer &chunk) {
	message.Write<ChunkType>(type);
	message.Write<size_t>(chunk.ReadAvailable());
	chunk.Read(message, chunk.ReadAvailable());
}

template<typename T>
static void MakeChunk(util::Buffer &message, ChunkType type, T &t) {
	message.Write<ChunkType>(type);
	message.Write<size_t>(util::Buffer::Size(t));
	message.Write(t);
}

InterfaceSniffer::MessageContext::~MessageContext() {
	//fprintf(stderr, "leaving message handling context for thread 0x%lx\n", thread.thread_id);
	message = {vtable.real_vtable_addr}; // restore vtable

	uint32_t result = (uint32_t) thread.GetContext().x[0];

	// commit message
	util::Buffer message;
	{ // ResultCode
		MakeChunk(message, ChunkType::ResultCode, result);
	}
	{ // RequestPas
		util::Buffer chunk;
		chunk.Write<uint64_t>(rq_pas.pointer);
		chunk.Write<uint64_t>(rq_pas.size);
		AddChunk(message, ChunkType::RequestPas, chunk);
	}
	{ // RequestData
		MakeChunk(message, ChunkType::RequestData, rq_data);
	}
	if(meta_info) { // MetaInfo
		MakeChunk(message, ChunkType::MetaInfo, *meta_info);
	}
	if(rs_pas) { // ResponsePas
		util::Buffer chunk;
		chunk.Write<uint64_t>(rs_pas->pointer);
		chunk.Write<uint64_t>(rs_pas->size);
		AddChunk(message, ChunkType::ResponsePas, chunk);
	}
	if(rs_data) { // ResponseData
		MakeChunk(message, ChunkType::ResponseData, *rs_data);
	}
	if(buffers) { // Buffers
		util::Buffer chunk;
		for(auto &i : *buffers) {
			chunk.Write<uint64_t>(i.size());
			chunk.Write(i);
		}
		AddChunk(message, ChunkType::Buffers, chunk);
	}

	owner.ilia.pcap_writer.WriteEPB(owner.interface_id, 0, message.ReadAvailable(), message.ReadAvailable(), message.Read(), nullptr);
}

InterfaceSniffer::MessageContext::PrepareForProcess::PrepareForProcess(
	MessageContext &ctx,
	Process::Thread &thread,
	uint64_t _this,
	Process::RemotePointer<nn::sf::cmif::CmifMessageMetaInfo> info) :
	CommonContext<MessageContext>(ctx, thread) {
	owner.meta_info.emplace(*info);
}

InterfaceSniffer::MessageContext::BeginPreparingForReply::BeginPreparingForReply(
	MessageContext &ctx,
	Process::Thread &thread,
	uint64_t _this,
	Process::RemotePointer<nn::sf::detail::PointerAndSize> pas) :
	CommonContext<MessageContext>(ctx, thread),
	pas(pas) {
}

InterfaceSniffer::MessageContext::BeginPreparingForReply::~BeginPreparingForReply() {
	owner.rs_pas.emplace(*pas);
}

InterfaceSniffer::MessageContext::SetBuffers::SetBuffers(
	MessageContext &ctx,
	Process::Thread &thread,
	uint64_t _this,
	Process::RemotePointer<nn::sf::detail::PointerAndSize> pas_array) :
	CommonContext<MessageContext>(ctx, thread) {
	if(owner.meta_info) {
		owner.buffers.emplace(owner.meta_info->buffer_count);
		for(size_t i = 0; i < owner.meta_info->buffer_count; i++) {
			nn::sf::detail::PointerAndSize pas = pas_array[i];
			(*owner.buffers)[i].resize(pas.size);
			process.ReadBytes((*owner.buffers)[i], pas.pointer);
		}
	} else {
		fprintf(stderr, "WARNING: SetBuffers called without PrepareForProcess?\n");
	}
}

InterfaceSniffer::MessageContext::EndPreparingForReply::EndPreparingForReply(
	MessageContext &ctx,
	Process::Thread &thread,
	uint64_t _this) :
	CommonContext<MessageContext>(ctx, thread) {
	if(owner.rs_pas) {
		owner.rs_data.emplace(owner.rs_pas->size);
		process.ReadBytes(*owner.rs_data, owner.rs_pas->pointer);
	}
}

} // namespace ilia
