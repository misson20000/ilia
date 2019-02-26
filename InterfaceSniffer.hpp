#pragma once

#include "Ilia.hpp"
#include "Process.hpp"
#include "Traps.hpp"
#include "nn_sf.hpp"

namespace ilia {

class InterfaceSniffer {
 public:
	InterfaceSniffer(Ilia &ilia, Process::STable &s_table);
	InterfaceSniffer(const InterfaceSniffer &other) = delete;
	InterfaceSniffer(InterfaceSniffer &&other) = delete;
 private:
	Ilia &ilia;
	uint32_t interface_id;
	Process::STable &s_table;
	
	class MessageContext : public CommonContext<InterfaceSniffer> {
	 public:
		using Arguments = std::tuple<
		 uint64_t,
		 Process::RemotePointer<nn::sf::cmif::server::CmifServerMessage>,
		 Process::RemotePointer<nn::sf::detail::PointerAndSize>>;
		
		MessageContext(
			InterfaceSniffer &sniffer,
			Process::Thread &thread,
			uint64_t object,
			Process::RemotePointer<nn::sf::cmif::server::CmifServerMessage> message,
			Process::RemotePointer<nn::sf::detail::PointerAndSize> pas);
		~MessageContext();

	 private:
		Process::RemotePointer<nn::sf::cmif::server::CmifServerMessage> message;
		nn::sf::detail::PointerAndSize rq_pas;
		std::vector<uint8_t> rq_data;
		std::optional<nn::sf::cmif::CmifMessageMetaInfo> meta_info;
		std::optional<nn::sf::detail::PointerAndSize> rs_pas;
		std::optional<std::vector<uint8_t>> rs_data;
		std::optional<std::vector<std::vector<uint8_t>>> buffers;
		
		class PrepareForProcess : public CommonContext<MessageContext> {
			// nn::Result CmifServerMessage::PrepareForProcess(CmifMessageMetaInfo *info);
		 public:
			using Arguments = std::tuple<
			 uint64_t,
			 Process::RemotePointer<nn::sf::cmif::CmifMessageMetaInfo>>;
			
			PrepareForProcess(
				MessageContext &ctx,
				Process::Thread &thread,
				uint64_t _this,
				Process::RemotePointer<nn::sf::cmif::CmifMessageMetaInfo> info);
		};

		/*
		class GetInObjects : public CommonContext<MessageContext>  {
		};
		*/

		class BeginPreparingForReply : public CommonContext<MessageContext>  {
		 public:
			using Arguments = std::tuple<
			 uint64_t,
			 Process::RemotePointer<nn::sf::detail::PointerAndSize>>;

			BeginPreparingForReply(
				MessageContext &ctx,
				Process::Thread &thread,
				uint64_t _this,
				Process::RemotePointer<nn::sf::detail::PointerAndSize> pas);
			~BeginPreparingForReply();
		 private:
			Process::RemotePointer<nn::sf::detail::PointerAndSize> pas;
		};

		class SetBuffers : public CommonContext<MessageContext>  {
		 public:
			using Arguments = std::tuple<
				uint64_t,
				Process::RemotePointer<nn::sf::detail::PointerAndSize>>;

			SetBuffers(
				MessageContext &ctx,
				Process::Thread &thread,
				uint64_t _this,
				Process::RemotePointer<nn::sf::detail::PointerAndSize> pas_array);
		};

		/*
		class SetOutObjects : public CommonContext<MessageContext>  {
		};
		class SetOutNativeHandles : public CommonContext<MessageContext>  {
		};
		class BeginPreparingForErrorReply : public CommonContext<MessageContext>  {
		};*/

		class EndPreparingForReply : public CommonContext<MessageContext> {
		 public:
			using Arguments = std::tuple<
			 uint64_t>;

			EndPreparingForReply(
				MessageContext &ctx,
				Process::Thread &thread,
				uint64_t _this);
		};
		
		VTableTrap<
			MessageContext, // parent context
			SmartContext<PrepareForProcess>, // PrepareForProcess
			CommonContext<MessageContext>, // OverwriteClientProcessId
			CommonContext<MessageContext>, // GetBuffers
			CommonContext<MessageContext>, // GetInNativeHandles 
			CommonContext<MessageContext>, // GetInObjects
			SmartContext<BeginPreparingForReply>, // BeginPreparingForReply
			SmartContext<SetBuffers>, // SetBuffers
			CommonContext<MessageContext>, // SetOutObjects
			CommonContext<MessageContext>, // SetOutNativeHandles
			CommonContext<MessageContext>, // BeginPreparingForErrorReply
			SmartContext<EndPreparingForReply> // EndPreparingForReply
			> vtable;
		StackHolder<decltype(vtable)::VTableType> holder;
	}; // class MessageContext
	
	FunctionPointerTrap<SmartContext<MessageContext>, InterfaceSniffer> s_table_trap;
};

} // namespace ilia
