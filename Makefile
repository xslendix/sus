build:
	cc -Wall -lcrypt -I. sus.c -o sus

all: build install

clean:
	rm -vrf sus

install:
ifneq ($(shell id -u), 0)
	@echo "You must be root to perform this action."
else
	cp sus /usr/bin/sus
	chmod 4711 /usr/bin/sus
endif

uninstall: clean
ifneq ($(shell id -u), 0)
	@echo "You must be root to perform this action."
else
	rm -f /usr/bin/sus
endif

