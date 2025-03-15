mbedtls_src = \
	$(wildcard mbedtls/library/*.c) \
	$(wildcard mbedtls/tf-psa-crypto/core/*.c) \
	$(wildcard mbedtls/tf-psa-crypto/drivers/builtin/src/*.c)

mbedtls_o = $(patsubst %.c, %.wasm.o, $(mbedtls_src))

HERE = $(CURDIR)
SRC = $(wildcard src/*.cpp)
HEADERS = $(wildcard include/*.cpp)
OBJS = $(patsubst %.cpp, %.wasm.o, $(SRC))

LDFLAGS += -sALLOW_MEMORY_GROWTH=1 -sEMBIND_AOT=1 -sFILESYSTEM=0 \
		   -sMODULARIZE=1 -sSINGLE_FILE=1 -sEXPORT_NAME=mitmjs

CFLAGS += \
	-flto -fno-exceptions \
	-I$(HERE) \
	-I$(HERE)/mbedtls/include \
	-I$(HERE)/mbedtls/tf-psa-crypto/include/ \
	-I$(HERE)/mbedtls/tf-psa-crypto/core \
	-I$(HERE)/mbedtls/tf-psa-crypto/drivers/builtin/include \
	-I$(HERE)/mbedtls/tf-psa-crypto/drivers/builtin/src/ \
	-I$(HERE)/mbedtls/framework/psasim/include \
	-DMBEDTLS_USER_CONFIG_FILE=\"mitm_mbedtls_config.h\" \
	-DTF_PSA_CRYPTO_USER_CONFIG_FILE=\"mitm_mbedtls_config.h\" \

.PHONY: format clean

mitm.js: $(OBJS) $(mbedtls_o)
	emcc -flto -Os $(LDFLAGS) -lembind -o $@ $^

%.wasm.o: %.c
	emcc -Os -c $(CFLAGS) -o $*.wasm.o $*.c

%.wasm.o: %.cpp $(HEADERS)
	emcc -std=c++20 -Os -c $(CFLAGS) -I$(HERE)/include -o $*.wasm.o $*.cpp

format:
	clang-format -i src/*.cpp include/*.hpp

clean:
	rm -f $(mbedtls_o) $(OBJS)

