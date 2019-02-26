# include libtransistor rules
ifndef LIBTRANSISTOR_HOME
    $(error LIBTRANSISTOR_HOME must be set)
endif
include $(LIBTRANSISTOR_HOME)/libtransistor.mk

ILIA_OBJECTS := Ilia.o Process.o InterfaceSniffer.o Buffer.o pcapng.o util.o ini.o
LIBIBERTY_OBJECTS := cp-demangle.o

ILIA_CXX_FLAGS := -g -Og -I vendor

LIBIBERTY_CC_FLAGS := -I libiberty/include/ -DHAVE_STDLIB_H -DHAVE_STRING_H -DHAVE_ALLOCA_H -DHAVE_LIMITS_H

BUILD_PFS0 := build_pfs0

ATMOSPHERE_DIR := build/atmosphere
ATMOSPHERE_ILIA_TITLE_ID := 0100000000007200
ATMOSPHERE_ILIA_TITLE_DIR := $(ATMOSPHERE_DIR)/titles/$(ATMOSPHERE_ILIA_TITLE_ID)
ATMOSPHERE_ILIA_TARGETS := $(addprefix $(ATMOSPHERE_ILIA_TITLE_DIR)/,exefs.nsp flags/boot2.flag)

all: build/ilia.nro build/ilia.nso $(ATMOSPHERE_ILIA_TARGETS)

clean:
	rm -rf build

$(ATMOSPHERE_ILIA_TITLE_DIR)/exefs.nsp: build/ilia/exefs/main build/ilia/exefs/main.npdm
	mkdir -p $(@D)
	$(BUILD_PFS0) build/ilia/exefs/ $@

$(ATMOSPHERE_ILIA_TITLE_DIR)/flags/boot2.flag:
	mkdir -p $(@D)
	touch $@

build/ilia/exefs/main.npdm: ilia.json
	mkdir -p $(@D)
	npdmtool $< $@

build/%/exefs/main: build/%.nso
	mkdir -p $(@D)
	cp $< $@

build/%.o: %.c
	mkdir -p $(@D)
	$(CC) $(CC_FLAGS) $(ILIA_CC_FLAGS) -c -o $@ $<

build/%.o: %.cpp
	mkdir -p $(@D)
	$(CXX) $(CXX_FLAGS) $(ILIA_CXX_FLAGS) -c -o $@ $<

build/%.squashfs.o: build/%.squashfs
	mkdir -p $(@D)
	$(LD) -s -r -b binary -m aarch64elf -T $(LIBTRANSISTOR_HOME)/fs.T -o $@ $<

build/ilia.nro.so: $(addprefix build/,$(ILIA_OBJECTS)) build/libiberty/libiberty.a $(LIBTRANSITOR_NRO_LIB) $(LIBTRANSISTOR_COMMON_LIBS)
	mkdir -p $(@D)
	$(LD) $(LD_FLAGS) -o $@ $(addprefix build/,$(ILIA_OBJECTS)) $(LIBTRANSISTOR_NRO_LDFLAGS) -L build/libiberty/ -liberty

build/ilia.nso.so: $(addprefix build/,$(ILIA_OBJECTS)) build/libiberty/libiberty.a $(LIBTRANSITOR_NSO_LIB) $(LIBTRANSISTOR_COMMON_LIBS)
	mkdir -p $(@D)
	$(LD) $(LD_FLAGS) -o $@ $(addprefix build/,$(ILIA_OBJECTS)) $(LIBTRANSISTOR_NSO_LDFLAGS) -L build/libiberty/ -liberty

build/libiberty/libiberty.a: $(addprefix build/libiberty/,$(LIBIBERTY_OBJECTS))
	mkdir -p $(@D)
	rm -f $@
	$(AR) $(AR_FLAGS) $@ $+

build/libiberty/%.o: libiberty/%.c
	mkdir -p $(@D)
	$(CC) $(CC_FLAGS) $(LIBIBERTY_CC_FLAGS) -c -o $@ $<
