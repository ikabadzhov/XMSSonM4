CC     = arm-none-eabi-gcc
CFLAGS = -Wall -Wextra -Wpedantic -O0 -g -mthumb -mcpu=cortex-m4 -mfloat-abi=hard -mfpu=fpv4-sp-d16
AR     = arm-none-eabi-gcc-ar

CC_HOST = gcc
CFLAGS_HOST = -Wall -Wextra -O3
AR_HOST = gcc-ar

SOURCES = hash_address.c hash.c params.c utils.c wots.c xmss_commons.c xmss_core.c xmss.c 
HEADERS = api.h hash_address.h hash.h params.h utils.h wots.h xmss_commons.h xmss_core.h xmss.h 
OBJECTS = hash_address.o hash.o params.o utils.o wots.o xmss_commons.o xmss_core.o xmss.o 

OBJECTS_HOST = $(patsubst %.o,%_host.o,$(OBJECTS))

libpqm4.a: $(OBJECTS)
	$(AR) rcs $@ $(OBJECTS)

libpqhost.a: $(OBJECTS_HOST)
	$(AR_HOST) rcs $@ $(OBJECTS_HOST)

%_host.o: %.c $(HEADERS)
	$(CC_HOST) -I$(INCPATH) $(CFLAGS_HOST) -c -o $@ $<

%.o: %.c $(HEADERS)
	$(CC) -I$(INCPATH) $(CFLAGS) -c -o $@ $<

.PHONY: clean
.INTERMEDIATE: $(OBJECTS)

clean:
	-rm -f libpqhost.a
	-rm -f libpqm4.a
	-rm -f *.o
