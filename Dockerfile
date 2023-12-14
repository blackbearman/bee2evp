FROM ubuntu:latest

RUN apt-get clean 
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install cmake -y -q

RUN apt-get install -y -q \
	build-essential \
	git \
	libssl-dev

WORKDIR '/usr/src'
RUN git clone --recurse-submodules https://github.com/bcrypto/bee2evp.git
RUN mkdir ./bee2evp/build

WORKDIR '/usr/src/bee2evp/build'
RUN cmake ..
RUN make
RUN make install

RUN openssl version
RUN openssl version -d

RUN openssl engine -t bee2evp