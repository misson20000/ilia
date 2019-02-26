#pragma once

namespace nn {
namespace sf {
namespace detail {

struct PointerAndSize {
	uint64_t pointer;
	size_t size;
};

} // namespace detail

struct NativeHandle {
	handle_t handle;
	bool valid;
};

namespace cmif {

struct CmifMessageMetaInfo {
	bool has_pid;
	uint64_t bytes_in;
	uint64_t bytes_out;
	uint32_t buffer_count;
	uint32_t in_interfaces;
	uint32_t out_interfaces;
	uint32_t in_handle_count;
	uint32_t out_handle_count;
	uint32_t buffers[16];
	uint32_t in_handles[8];
	uint32_t out_handles[8];
};

namespace server {

struct CmifServerObjectInfo {
	void *object;
	result_t (**s_Table)(void*, void*, detail::PointerAndSize*);
};

struct CmifServerMessage {
	uint64_t vtable;
};

} // namespace server
} // namespace cmif

} // namespace sf
} // namespace nn
