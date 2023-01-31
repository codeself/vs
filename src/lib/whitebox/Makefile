objects = $(patsubst %.c,%.o,$(wildcard *.c))

all:$(objects)
	@echo "$(objects)"
	gcc -shared -o libvs-wb-aes.so $(objects) -lm4ri
	
clean:
	rm -f *.o
