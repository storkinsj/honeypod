# Use an appropriate base image
FROM alpine:latest

ARG UNBOUND_VERSION=1.17.1
ENV UNBOUND_VERSION ${UNBOUND_VERSION} 
ENV UNBOUND_DOWNLOAD_URL "https://www.nlnetlabs.nl/downloads/unbound/unbound-"${UNBOUND_VERSION}".tar.gz"
ENV UNBOUND_BUILD_DIR "unbound-"${UNBOUND_VERSION}
ENV UNBOUND_TARBALL "unbound-"${UNBOUND_VERSION}.tar.gz
    

# Set the working directory in the container
WORKDIR /app
RUN mkdir /app/honeypod
RUN mkdir /app/tests

# Copy the package files to the container
COPY honeypod/ /app/honeypod
COPY tests /app/tests
COPY setup.py /app/
COPY _entrypointCode/* /app/
COPY syslog-ng/ /etc/

# Create service principles
RUN addgroup syslogng
RUN adduser --ingroup syslogng -D syslognguser
RUN addgroup unbound
RUN adduser --ingroup unbound -D unbound
RUN addgroup p0f
RUN adduser --ingroup p0f -D p0f

# Install dependencies

# First get networking tools to discover our IP address
# This will be used to redirect network traffic to Honeypod
RUN apk update && apk upgrade && apk add --no-cache \
    ca-certificates \
    build-base \
    linux-headers \
    libc-dev \
    openssl-dev \
    expat-dev \
    apk-tools \
    gnupg \
    curl \
    file \
    zip \
    binutils \
    jansson \
    jansson-dev \
    libcap \
    libpcap \
    libpcap-dev \
    python3-dev \
    python3 \
    py3-pip \
    swig \
    syslog-ng \
    && pip3 install --upgrade pip


#RUN apk --no-cache add --virtual .build-deps \
#    build-base \                              
#    libc-dev \                                
#    openssl-dev \                             
#    expat-dev \                               
#    apk-tools \
#    jansson-dev \                               
#    libpcap-dev \     
#    zip                           


# Compile Unbound
#    We install unbound package to get alpine service created correctly. 
# We must compile the pythonmod addition into unbound and install that so that 
# we have support for domainfilter which is mission critical for honeypod.

RUN wget $UNBOUND_DOWNLOAD_URL
RUN tar -zxvf $UNBOUND_TARBALL
RUN cd $UNBOUND_BUILD_DIR && ./configure --with-pythonmodule && make && make install

# Cleanup
# RUN rm -rf unbound* && apk del .build-deps
RUN rm $UNBOUND_TARBALL && rm -rf $UNBOUND_BUILD_DIR

#
# Compile p0f
#

RUN wget https://codeload.github.com/p0f/p0f/zip/refs/heads/master -O master.zip
RUN unzip master.zip
RUN cd p0f-master && source ./build.sh && setcap cap_sys_chroot,cap_setgid,cap_net_raw=+ep /opt/p0f/p0f
# Cleanup
RUN rm master.zip




# Install all python dependencies
RUN pip install -r /app/honeypod/requirements.txt

RUN chmod +x /app/bootstrap.sh
RUN chmod +x /app/honeypod/P0fMonitor.py

#USER syslognguser

# More or less document what we want exposed
EXPOSE 0:1024

# Set the entry point command for the container
ENTRYPOINT ["/app/bootstrap.sh"]

