CXX ?= g++
AR  ?= ar
RL  = ranlib
CP  = cp -r

DIRSRC  = src
DIRTEST = test
DIRLIB  = lib
DIRBIN  = bin
DIROBJ  = obj

TARGET = $(DIRLIB)/libtwofish.a

LSRCS += $(DIRSRC)/tfish.cpp
LSRCS += $(DIRSRC)/libtwofish.cpp

TSRCS += $(DIRTEST)/test.cpp

LOBJS = $(LSRCS:$(DIRSRC)/%.cpp=$(DIROBJ)/%.o)
TOBJS = $(TSRCS:$(DIRTEST)/%.cpp=$(DIROBJ)/%.o)

#DFLAGS += -g -DDEBUG_LIBTWOFISH
DFLAGS +=
CFLAGS += -I$(DIRSRC)
CFLAGS += $(DFLAGS)
LFLAGS += -L$(DIRLIB) -ltwofish
LAOPT  =

# automatic architecture sensing.
KRNL := $(shell uname -s)
KVER := $(shell uname -r | cut -d . -f1) 
ARCH := $(shell uname -m)

ifeq ($(KRNL),Darwin)
	# MacOSX using llvm-g++
    CXX = llvm-g++
    ifeq ($(shell test $(KVER) -gt 19; echo $$?),0)
        LAOPT += -arch x86_64 -arch arm64
        LAOPT += -mmacosx-version-min=11.0
    endif
else ifeq ($(KRNL),Linux)
	CFLAGS += -std=c++11	
else
    STRIPKRNL = $(shell echo $(KRNL) | cut -d - -f1)
    ifeq ($(STRIPKRNL),MINGW64_NT)
        CFLAGS += -std=c++11
        LFLAGS += -s -static
    endif
endif

# Let give some speed optimization at code generation
CFLAGS += -Os

.PHONY:	prepare clean cleantest cleanlibtest

all: prepare $(TARGET)
test: $(DIRBIN)/test
libtest: $(DIRBIN)/libtest

prepare:
	@mkdir -p $(DIROBJ)
	@mkdir -p $(DIRLIB)
	@mkdir -p $(DIRBIN)

clean:
	@rm -rf $(LOBJS)
	@rm -rf $(TOBJS)
	@rm -rf $(TARGET)
	@rm -rf $(DIRLIB)/*.h
	@rm -rf $(DIRBIN)/test

cleantest:
	@rm -rf $(DIRBIN)/test

cleanlibtest:
	@rm -rf $(DIRBIN)/libtest

$(LOBJS): $(DIROBJ)/%.o: $(DIRSRC)/%.cpp
	@$(CXX) $(CFLAGS) $(LAOPT) -c $< -o $@

$(TOBJS): $(DIROBJ)/%.o: $(DIRTEST)/%.cpp
	@$(CXX) -I$(DIRSRC) -I$(DIRLIB) $(LAOPT) $(DFLAGS) -c $< -o $@

$(TARGET): $(LOBJS)
	@echo "Generating $@ ..."
	@rm -rf $@
	@$(AR) -cr $@ $^
	@$(RL) $@
	@$(CP) -f $(DIRSRC)/twofish.h $(DIRLIB)

$(DIRBIN)/test: $(TOBJS) $(TARGET)
	@echo "Building test ..."
	@$(CXX) -I$(DIRSRC) $< $(LFLAGS) $(LAOPT) -o $@

$(DIRBIN)/libtest: $(TARGET) $(DIRTEST)/libtest.cpp
	@echo "Building libtest ... "
	@$(CXX) -I$(DIRLIB) $(DIRTEST)/libtest.cpp $(DFLAGS) $(LFLAGS) $(LAOPT) -o $@

