TARGET = liblodepng.so
LIBS = 
CC = gcc -shared -fPIC
CFLAGS = -D LODEPNG_NO_COMPILE_DECODER -D LODEPNG_NO_COMPILE_DISK -D LODEPNG_NO_COMPILE_ANCILLARY_CHUNKS -D LODEPNG_NO_COMPILE_ERROR_TEXT -D LODEPNG_NO_COMPILE_CPP 

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
	sudo cp lodepng.h /usr/local/include
	sudo cp $(TARGET) /usr/local/lib
	sudo ldconfig

clean:
	-rm -f *.o
	-rm -f $(TARGET)
