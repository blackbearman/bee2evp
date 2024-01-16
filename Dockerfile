FROM btls/bee2evp

RUN apt-get update && apt-get install -y \
    automake autoconf libtool libtool-bin gcc \
    libltdl7 libltdl-dev \
    libxml2 libxml2-dev libxslt1.1 libxslt1-dev \
    openssl libssl3 libssl-dev


WORKDIR /usr/src

RUN git clone https://github.com/lsh123/xmlsec.git

WORKDIR /usr/src/xmlsec

RUN bash autogen.sh
RUN ./configure --enable-openssl3-engines --enable-static-linking
RUN make
RUN make install

WORKDIR /usr/src
