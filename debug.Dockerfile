FROM openssl:debug

RUN apt-get clean 
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install cmake pkg-config -y -q

COPY . /usr/src/bee

WORKDIR '/usr/src/bee'
RUN mkdir -p ./_build

WORKDIR '/usr/src/bee/_build'
RUN cmake -DCMAKE_BUILD_TYPE=Debug ..
RUN make
RUN make install

RUN openssl version
RUN openssl version -d

#RUN bee2cmd es print


RUN sed -i -e '/^.default_sect.$/a activate = 1' /usr/local/ssl/openssl.cnf

RUN sed -i -e '/^.provider_sect.$/a bee2pro = bee2pro_section' /usr/local/ssl/openssl.cnf

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
default_algorithms = ALL \n\#########################/g' /usr/local/ssl/openssl.cnf

RUN openssl list -providers

RUN	OPENSSL_TRACE=ENCODER openssl genpkey -provider bee2pro -genparam \
    -algorithm bign -pkeyopt params:bign-curve256v1 -out params256 

RUN cat params256

RUN OPENSSL_TRACE=DECODER openssl genpkey -provider bee2pro \
-paramfile params256 -out privkey_plain.pem 

RUN cat privkey_plain.pem

RUN openssl pkey -provider bee2pro -in privkey_plain.pem -pubout -out public_key.pem 

RUN cat public_key.pem
