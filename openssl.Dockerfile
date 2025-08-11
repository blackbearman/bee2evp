FROM ubuntu:noble
 
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install build-essential make -y -q
RUN apt-get clean

COPY . /usr/src

WORKDIR '/usr/src'
RUN ./Configure --debug enable-trace '-Wl,--enable-new-dtags,-rpath,$(LIBRPATH)'
RUN make
RUN make install

RUN openssl version