FROM ubuntu:noble

RUN apt-get clean 
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install cmake -y -q

RUN apt-get install -y -q \
	build-essential \
	git \
	libssl-dev \
	pkg-config \
	ed

COPY . /usr/src

WORKDIR '/usr/src'
RUN git submodule update --init
RUN mkdir -p ./_build

WORKDIR '/usr/src/_build'
RUN cmake ..
RUN make
RUN make install

RUN openssl version
RUN openssl version -d

RUN sed -i -e '/^.openssl_init.$/a engines = engine_section' /usr/lib/ssl/openssl.cnf

RUN sed -i -e '/^.default_sect.$/a activate = 1' /usr/lib/ssl/openssl.cnf

RUN sed -i -e '/^.provider_sect.$/a bee2pro = bee2pro_section' /usr/lib/ssl/openssl.cnf

RUN sed -i -e '0,/[#]\{5,\}/s/[#]\{5,\}/[engine_section] \n\
bee2evp = bee2evp_section \n\
\n\
[bee2pro_section] \n\
identity = bee2pro \n\
module = \/usr\/local\/lib\/libbee2evp.so \n\
activate = 1 \n\
\n\
[bee2evp_section] \n\
engine_id = bee2evp \n\
dynamic_path = \/usr\/local\/lib\/libbee2evp.so \n\
default_algorithms = ALL \n\#########################/g' /usr/lib/ssl/openssl.cnf

RUN sed -i '/.*new_oids \].*/a \
bpki = 1.2.112.0.2.0.34.101.78 \n\
bpki-role-ca0 = \$\{bpki\}.2.0 \n\
bpki-role-ca1 = \$\{bpki\}.2.1 \n\
bpki-role-ca2 = \$\{bpki\}.2.2 \n\
bpki-role-aa  = \$\{bpki\}.2.10 \n\
bpki-role-ra = \$\{bpki\}.2.20 \n\
bpki-role-ocsp = \$\{bpki\}.2.30 \n\
bpki-role-tsa = \$\{bpki\}.2.31 \n\
bpki-role-dvcs = \$\{bpki\}.2.32 \n\
# identification servers \n\
bpki-role-ids = \$\{bpki\}.2.33 \n\
bpki-role-tls = \$\{bpki\}.2.50 \n\
# natural persons \n\
bpki-role-np = \$\{bpki\}.2.60 \n\
# foreign natural persons \n\
bpki-role-fnp = \$\{bpki\}.2.61 \n\
# legal representatives \n\
bpki-role-lr = \$\{bpki\}.2.62 \n\
# autonomous cryptographic devices \n\
bpki-role-acd = \$\{bpki\}.2.70 \n\
# server of Terminal Mode \n\
bpki-eku-serverTM = \${bpki}.3.1 \n\
# client of Terminal Mode \n\
bpki-eku-clientTM = \$\{bpki\}.3.2 \n\
# Enroll1 request \n\
bpki-ct-enroll1-req = \$\{bpki\}.5.1 \n\
# Enroll2 request \n\
bpki-ct-enroll2-req = \$\{bpki\}.5.2 \n\
# Reenroll request \n\
bpki-ct-reenroll-req = \$\{bpki\}.5.3 \n\
# Spawn request \n\
bpki-ct-spawn-req = \$\{bpki\}.5.4 \n\
# Setpwd request \n\
bpki-ct-setpwd-req = \$\{bpki\}.5.5 \n\
# Revoke request \n\
bpki-ct-revoke-req = \$\{bpki\}.5.6 \n\
# BPKIResp \n\
bpki-ct-resp = \$\{bpki\}.5.7 \n\
' /usr/lib/ssl/openssl.cnf

RUN cat /usr/lib/ssl/openssl.cnf

RUN openssl list -providers

RUN openssl engine -t bee2evp

RUN echo -n "hello world" | openssl dgst -engine bee2evp -belt-hash

RUN echo -n "hello world" | openssl dgst -provider bee2pro -belt-hash

RUN echo -n "hello world" | openssl dgst -engine bee2evp -bash256

RUN echo -n "hello world" | openssl dgst -provider bee2pro -bash256

RUN echo -n "hello world" | openssl dgst -engine bee2evp -bash384

RUN echo -n "hello world" | openssl dgst -provider bee2pro -bash384

RUN echo -n "hello world" | openssl dgst -engine bee2evp -bash512

RUN echo -n "hello world" | openssl dgst -provider bee2pro -bash512

RUN ls .. -a

RUN openssl enc -belt-ecb128 -provider bee2pro -in ../.gitmodules -out text.bin -K 00112233445566778899AABBCCDDEEFF

RUN od -t x1 -An text.bin

RUN openssl enc -belt-ecb128 -engine bee2evp -in ../.gitmodules -out text2.bin -K 00112233445566778899AABBCCDDEEFF

RUN od -t x1 -An text2.bin