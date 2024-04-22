# usr/src/tests/bign# gcc sign2.c -I../../include -I/usr/include/libxml2 -L../../src/.libs -lltdl -lxmlsec1 -lxslt -lxml2
# LD_LIBRARY_PATH=/usr/local/lib make check
#
PROGRAMS = sign2 

CC	= gcc
CFLAGS	+= -g $(shell ../../xmlsec1-config --cflags) -DUNIX_SOCKETS -Wall -Wextra
LDLIBS	+= -g $(shell ../../xmlsec1-config --libs)

all: $(PROGRAMS)

clean:
	rm -rf $(PROGRAMS)

check: $(PROGRAMS)
	./sign2    sign2-doc.xml     privkey.pem
