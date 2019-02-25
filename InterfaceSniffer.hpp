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

		nn::sf::cmif::CmifMessageMetaInfo meta_info;
		
	 private:
		Process::RemotePointer<nn::sf::cmif::server::CmifServerMessage> message;
		
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
			~PrepareForProcess();
		};
		
		/*class OverwriteClientProcessId : public CommonContext<MessageContext>  {
		};
		class GetBuffers : public CommonContext<MessageContext>  {
		};
		class GetInNativeHandles : public CommonContext<MessageContext>  {
		};
		class GetInObjects : public CommonContext<MessageContext>  {
		};*/

		/*
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
		};*/

		/*
		class SetBuffers : public CommonContext<MessageContext>  {
		};
		class SetOutObjects : public CommonContext<MessageContext>  {
		};
		class SetOutNativeHandles : public CommonContext<MessageContext>  {
		};
		class BeginPreparingForErrorReply : public CommonContext<MessageContext>  {
		};*/
		VTableTrap<
			MessageContext, // parent context
			SmartContext<PrepareForProcess>,
			/*
			OverwriteClientProcessId,
			GetBuffers,
			GetInNativeHandles,
			GetInObjects, */
			CommonContext<MessageContext>,
			CommonContext<MessageContext>,
			CommonContext<MessageContext>,
			CommonContext<MessageContext>,
			/* BeginPreparingForReply */
			CommonContext<MessageContext>,
			//SmartContext<BeginPreparingForReply>,
			/*
			SetBuffers,
			SetOutObjects,
			SetOutNativeHandles,
			BeginPreparingForErrorReply*/
			CommonContext<MessageContext>,
			CommonContext<MessageContext>,
			CommonContext<MessageContext>,
			CommonContext<MessageContext>,
			CommonContext<MessageContext>
			> vtable;
		StackHolder<decltype(vtable)::VTableType> holder;
	}; // class MessageContext
	
	FunctionPointerTrap<SmartContext<MessageContext>, InterfaceSniffer> s_table_trap;
};

} // namespace ilia
