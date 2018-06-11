#include<stdint.h>
#include<string.h>
#include<libtransistor/types.h>
#include<libtransistor/svc.h>
#include<libtransistor/util.h>

void memcpy64(void *dest, const void *src, size_t size) {
	uint64_t *dest64 = (uint64_t*) dest;
	uint64_t *src64 = (uint64_t*) src;
	for(size_t i = 0; i < size/sizeof(uint64_t); i++) {
		dest64[i] = src64[i];
	}
}

struct PointerAndSize {
	void *ptr;
	size_t size;
};

uint64_t mitm(void *this, void *message, struct PointerAndSize *pas, uint32_t pipe_index);

#define def_mitm(id) uint64_t mitm ## id(void *this, void *message, struct PointerAndSize *pas) { \
		return mitm(this, message, pas, id); \
	}

def_mitm(0);
def_mitm(1);
def_mitm(2);
def_mitm(3);
def_mitm(4);
def_mitm(5);
def_mitm(6);
def_mitm(7);
def_mitm(8);
def_mitm(9);
def_mitm(10);
def_mitm(11);
def_mitm(12);
def_mitm(13);
def_mitm(14);
def_mitm(15);

const void *mitm_funcs[] = {
	mitm0, mitm1, mitm2, mitm3,
	mitm4, mitm5, mitm6, mitm7,
	mitm8, mitm9, mitm10, mitm11,
	mitm12, mitm13, mitm14, mitm15,
};

typedef uint64_t (*dispatch_fptr)(void*, void*, struct PointerAndSize*);

typedef struct {
	bool has_initialized;
	session_h writer; // ilia::IMessageWriter
	dispatch_fptr dispatch;
} logger_t;

typedef struct heap_info_t {
	bool has_initialized;
	void *heap;
	session_h proxy_service; // ilia::IProxyService
	logger_t loggers[ARRAY_LENGTH(mitm_funcs)];
} heap_info_t;

#define LOG_RESPONSES 1
#define PARSE_X_DESCRIPTORS 1
#define PARSE_A_DESCRIPTORS 1
#define PARSE_B_DESCRIPTORS 1
#define PARSE_C_DESCRIPTORS 1

typedef struct {
	dispatch_fptr *funcptr;
	dispatch_fptr dispatch;
} log_def_t;

void send_message(void *ipc_buffer, session_h s, uint32_t cmd, uint64_t arg, void *buffer_data, size_t buffer_size);
session_h get_proxy_service(heap_info_t *hi);
bool initialize_pipe(heap_info_t *hi, uint32_t pipe_index);

uint64_t mitm(void *this, void *message, struct PointerAndSize *pas, uint32_t pipe_index) {
	void *heap;
	svcSetHeapSize(&heap, 0x200000);
	heap_info_t *hi = heap + 0x1000;
	hi->heap = heap;

	if(!hi->loggers[pipe_index].has_initialized) {
		if(initialize_pipe(hi, pipe_index)) {
			return 0xEAEAB;
		}
	}
	
	void *tls;
	asm("mrs %0, tpidrro_el0"
	    : "=r"(tls) ::);
	
	memcpy64(heap, tls, 0x100);

	void *ipc_buffer = heap + 0x2000;
	void *buffer_copy_area = heap + 0x3000;

	logger_t *logger = &hi->loggers[pipe_index];
	session_h writer = logger->writer;
	send_message(ipc_buffer, writer, 0, (uint64_t) this, heap, 0x100); // OpenRequest

	uint32_t *mu32 = heap;
	int h = 0;

	uint32_t header0 = mu32[h++];
	uint32_t header1 = mu32[h++];

	int num_x_descriptors = (header0 >> 16) & 0xF;
	int num_a_descriptors = (header0 >> 20) & 0xF;
	int num_b_descriptors = (header0 >> 24) & 0xF;
	int num_w_descriptors = (header0 >> 28) & 0xF;

	int raw_data_size = header1 & 0x3FF;
	int c_descriptor_flags = (header1 >> 10) & 0xF;
	int num_c_descriptors = 0;
	if(c_descriptor_flags == 2) {
		num_c_descriptors = 1;
	} else if(c_descriptor_flags >= 2) {
		num_c_descriptors = c_descriptor_flags - 2;
	}
	
	uint64_t addr = 0;
	uint64_t size = 0;

	for(int i = 0; i < num_x_descriptors; i++) {
		uint32_t *field = &(mu32[h++]);
		uint32_t *lower = &(mu32[h++]);

		if(PARSE_X_DESCRIPTORS) {
			addr = 0;
			size = 0;
			
			addr|= *lower;
			addr|= (((uint64_t) *field >> 6) & 0b111) << 36;
			addr|= (((uint64_t) *field >> 12) & 0b1111) << 32;
			
			size = *field >> 16;

			if(addr != 0 && size != 0) {
				memcpy64(buffer_copy_area, (void*) addr, size);
				send_message(ipc_buffer, writer, 1, i, buffer_copy_area, size); // AppendXDescriptor
			}
		}
	}
	
	for(int i = 0; i < num_a_descriptors; i++) {
		if(PARSE_A_DESCRIPTORS) {
			size = mu32[h+0];
			addr = mu32[h+1];
			uint32_t field = mu32[h+2];
			addr|= (uint64_t) ((field >> 2) & 0b111) << 36;
			addr|= (uint64_t) ((field >> 28) & 0b1111) << 32;
			size|= (uint64_t) ((field >> 24) & 0b1111) << 32;

			if(addr != 0 && size != 0) {
				memcpy64(buffer_copy_area, (void*) addr, size);
				send_message(ipc_buffer, writer, 2, i, buffer_copy_area, size); /// AppendADescriptor
			}
		}
		h+= 3;
	}
	
	uint64_t ret = logger->dispatch(this, message, pas);

	if(LOG_RESPONSES) {
		memcpy64(heap + 0x100, tls, 0x100);
		send_message(ipc_buffer, writer, 3, (uint64_t) this, heap + 0x100, 0x100); // OpenResponse

		for(int i = 0; i < num_b_descriptors; i++) {
			if(PARSE_B_DESCRIPTORS) {
				size = mu32[h+0];
				addr = mu32[h+1];
				uint32_t field = mu32[h+2];
				addr|= (uint64_t) ((field >> 2) & 0b111) << 36;
				addr|= (uint64_t) ((field >> 28) & 0b1111) << 32;
				size|= (uint64_t) ((field >> 24) & 0b1111) << 32;

				if(addr != 0 && size != 0) {
					memcpy64(buffer_copy_area, (void*) addr, size);
					send_message(ipc_buffer, writer, 4, i, buffer_copy_area, size); /// AppendBDescriptor
				}
			}
			h+= 3;
		}

		h+= raw_data_size;
		
		for(int i = 0; i < num_c_descriptors; i++) {
			if(PARSE_C_DESCRIPTORS) {
				addr = mu32[h+0];
				uint32_t field = mu32[h+1];
				addr|= (uint64_t) (field & 0xFFFF) << 32;
				size = field >> 16;

				if(addr != 0 && size != 0) {
					memcpy64(buffer_copy_area, (void*) addr, size);
					send_message(ipc_buffer, writer, 5, i, buffer_copy_area, size);
				}
				
				h+= 2;
			}
		}
	}

	send_message(ipc_buffer, writer, 6, 0, NULL, 0); // CloseMessage
	
	return ret;
}

void send_message(void *ipc_buffer, session_h s, uint32_t cmd, uint64_t arg, void *buffer_data, size_t buffer_size) {
	/*
	  ipcm+0x0  | 04 00 10 00 09 00 00 00  bc 01 00 00 bc 01 00 00 | ................ |
	  ipcm+0x10 | 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 | ................ |
	  ipcm+0x20 | 53 46 43 49 00 00 00 00  8d 08 00 00 00 00 00 00 | SFCI............ |
	  ipcm+0x30 | 9e 09 00 00 00 00 00 00                          | ........         |
	 */
	const uint8_t messageu8[] = {
		0x04, 0x00, 0x10, 0x00, 0x0a, 0x00, 0x00, 0x00,  0xbc, 0x01, 0x00, 0x00, 0xbc, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x53, 0x46, 0x43, 0x49, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x9e, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
	};
	memcpy64(ipc_buffer, messageu8, sizeof(messageu8));
	uint32_t *messageu32 = ipc_buffer;
	
	uint64_t buffer_addr = (uint64_t) buffer_data;
	messageu32[2] = buffer_size & 0xFFFFFFFF;
	messageu32[3] = buffer_addr & 0xFFFFFFFF;
	messageu32[4] =
		(((buffer_addr >> 36) & 0b111) << 2) |
		(((buffer_size >> 32) & 0b1111) << 24) |
		(((buffer_addr >> 32) & 0b1111) << 28);
	messageu32[10] = cmd;
	*((uint64_t*) &messageu32[12]) = arg;

	svcSendSyncRequestWithUserBuffer(ipc_buffer, 0x1000, s);
}

session_h get_proxy_service(heap_info_t *hi) {
	void *heap = hi->heap;
	
	if(hi->has_initialized) {
		return hi->proxy_service;
	} else {
		session_h sm;
		svcConnectToNamedPort(&sm, "sm:");
		
		/*
		  ipcm+0x0  | 04 00 00 00 0a 00 00 00  00 00 00 00 00 00 00 00 | ................ |
		  ipcm+0x10 | 53 46 43 49 00 00 00 00  01 00 00 00 00 00 00 00 | SFCI............ |
		  ipcm+0x20 | 74 65 73 74 73 72 76 00  00 00 00 00 00 00 00 00 | testsrv......... |
		*/
		
		uint8_t ipct_get_service[] = {
			0x04, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x53, 0x46, 0x43, 0x49, 0x00, 0x00, 0x00, 0x00,  0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x69, 0x6c, 0x69, 0x61, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
		};
		memcpy64(heap, ipct_get_service, sizeof(ipct_get_service));
		svcSendSyncRequestWithUserBuffer(heap, 0x1000, sm);
		svcCloseHandle(sm);
		
		session_h proxy_service = *((uint32_t*) (heap + 0xc));
		
		send_message(heap + 0x3000, proxy_service, 2, 99, NULL, 0);

		hi->proxy_service = proxy_service;
		hi->has_initialized = true;
		return proxy_service;
	}
}

bool initialize_pipe(heap_info_t *hi, uint32_t i) {
	void *heap = hi->heap;
	
	session_h proxy_service = get_proxy_service(hi);
	
	uint8_t ipct_open_message_writer[] = {
		0x04, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x80,  0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x53, 0x46, 0x43, 0x49, 0x00, 0x00, 0x00, 0x00,  0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
	};
	memcpy64(heap, ipct_open_message_writer, sizeof(ipct_open_message_writer));
	*((uint32_t*) (heap + 0x30)) = i;
	svcSendSyncRequestWithUserBuffer(heap, 0x1000, proxy_service);
	
	send_message(heap + 0x3000, proxy_service, 2, 2, NULL, 0);
	
	if(*((uint32_t*) (heap + 0x18)) != 0) {
		return true;
	}
	
	send_message(heap + 0x3000, proxy_service, 2, 2, NULL, 0);
	
	session_h writer = *((uint32_t*) (heap + 0xc));
	log_def_t *def = heap + 0x20;
	
	hi->loggers[i].writer = writer;
	hi->loggers[i].dispatch = def->dispatch;
	
	send_message(heap + 0x3000, proxy_service, 2, 3, NULL, 0);

	hi->loggers[i].has_initialized = true;
	
	return false;
}
