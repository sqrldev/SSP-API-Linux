TARGET = libblowfish.so
LIBS = 
CC = gcc -shared -fPIC
CFLAGS = 

.PHONY: clean all default

default: $(TARGET)
all: default

OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))
HEADERS = $(wildcard *.h)

%.o: %.c $(HEADERS)
	$(CC) -c $(CFLAGS) $< -o $@

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(CC)  $(OBJECTS) -Wall $(LIBS) -o $@
	sudo cp blowfish.h /usr/local/include
	sudo cp $(TARGET) /usr/local/lib
	sudo ldconfig

clean:
	-rm -f *.o
	-rm -f $(TARGET)
