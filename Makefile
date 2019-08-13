
CC=gcc
CFLAGS=-fPIC -fno-stack-protector
PAM_MODULE_PATH=/lib/x86_64-linux-gnu/security

all: pam_winddown.so test_pam

%.o: src/%.c
		$(CC) -c -o $@ $< $(CFLAGS)

pam_winddown.so: pam_winddown.o
	$(CC) -shared -o pam_winddown.so pam_winddown.o -lpam -ldl

test_pam: test_pam.o
	$(CC) -o test_pam test_pam.o -lpam -lpam_misc

install:
	install -m 644 pam_winddown.so $(PAM_MODULE_PATH)/
	
clean:
	rm -f *.o
