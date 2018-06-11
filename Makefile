# include libtransistor rules
ifndef LIBTRANSISTOR_HOME
    $(error LIBTRANSISTOR_HOME must be set)
endif
include $(LIBTRANSISTOR_HOME)/libtransistor.mk

ILIA_OBJECTS := IMessageWriter.o IProxyService.o Ilia.o pcapng.o util.o ilia.squashfs.o Process.o Pipe.o
LIBIBERTY_OBJECTS := cp-demangle.o

INJECTION_LD_FLAGS := -Bsymbolic --gc-sections --no-undefined -T injection_link.T -L $(LIBTRANSISTOR_HOME)/lib/
INJECTION_CC_FLAGS := -g -fPIE -ffunction-sections -ffreestanding -fno-exceptions -fno-stack-protector -target aarch64-none-linux-gnu -Oz -mtune=cortex-a53 -nostdlib -nostdlibinc $(SYS_INCLUDES)

LIBIBERTY_CC_FLAGS := -I libiberty/include/ -DHAVE_STDLIB_H -DHAVE_STRING_H -DHAVE_ALLOCA_H -DHAVE_LIMITS_H

all: build/ilia.nro

clean:
	rm -rf build

build/%.o: %.c
	mkdir -p $(@D)
	$(CC) $(CC_FLAGS) $(ILIA_CC_FLAGS) -c -o $@ $<

build/%.o: %.cpp
	mkdir -p $(@D)
	$(CXX) $(CXX_FLAGS) $(ILIA_CXX_FLAGS) -c -o $@ $<

build/%.squashfs.o: build/%.squashfs
	mkdir -p $(@D)
	$(LD) -s -r -b binary -m aarch64elf -T $(LIBTRANSISTOR_HOME)/fs.T -o $@ $<

build/ilia.squashfs: build/injection_payload.bin
	mkdir -p $(@D)
	mksquashfs $^ $@ -comp xz -nopad -noappend

build/ilia.nro.so: $(addprefix build/,$(ILIA_OBJECTS)) build/libiberty/libiberty.a $(LIBTRANSITOR_NRO_LIB) $(LIBTRANSISTOR_COMMON_LIBS)
	mkdir -p $(@D)
	$(LD) $(LD_FLAGS) -o $@ $(addprefix build/,$(ILIA_OBJECTS)) $(LIBTRANSISTOR_NRO_LDFLAGS) -L build/libiberty/ -liberty

build/injection_payload.bin: build/injection_payload.elf
	aarch64-none-elf-objcopy -O binary $< $@

build/injection_payload.elf: injection_link.T build/injection_payload.o
	$(LD) $(INJECTION_LD_FLAGS) -o $@ $^ -ltransistor.nro

build/injection_payload.o: injection_payload.c
	$(CC) $(INJECTION_CC_FLAGS) -c -o $@ $<

build/libiberty/libiberty.a: $(addprefix build/libiberty/,$(LIBIBERTY_OBJECTS))
	mkdir -p $(@D)
	rm -f $@
	$(AR) $(AR_FLAGS) $@ $+

build/libiberty/%.o: libiberty/%.c
	mkdir -p $(@D)
	$(CC) $(CC_FLAGS) $(LIBIBERTY_CC_FLAGS) -c -o $@ $<
