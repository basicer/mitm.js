mbedtls_src = $(wildcard mbedtls/library/*.c)
mbedtls_o = $(patsubst %.c, %.o, $(mbedtls_src))

CFLAGS = -I. -Imbedtls/include

%.o: %.c
	emcc $(CFLAGS) -o $*.o $*.c

mitm.js: $(mbedtls_o)
	echo Doing $*