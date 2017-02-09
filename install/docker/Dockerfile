FROM ubuntu:16.04

LABEL maintainer "haas@informatik.uni-hamburg.de"

# Prepare system (packages and user)
RUN apt-get update && apt-get install apt-utils -y && apt-get upgrade -y && apt-get install sudo git cmake clang libcurl4-openssl-dev vim curl  -y
RUN adduser --disabled-password --gecos '' osquery
RUN usermod -aG sudo osquery
RUN echo "osquery       ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/local-lib.conf && ldconfig

# Download install and run script
WORKDIR /home/osquery/
USER osquery
ADD https://github.com/bro/bro-osquery/raw/master/install/install_ubuntu_16_04.sh /home/osquery/
RUN sudo chown osquery:osquery /home/osquery/install_ubuntu_16_04.sh && sudo chmod +x /home/osquery/install_ubuntu_16_04.sh
ADD https://github.com/bro/bro-osquery/raw/master/install/run.sh /home/osquery/
RUN sudo chown osquery:osquery /home/osquery/run.sh && sudo chmod +x /home/osquery/run.sh
RUN sudo chown -R osquery:osquery /home/osquery

# Create local osquery dependency folder
WORKDIR /usr/local/osquery
RUN sudo chown osquery:root /usr/local/osquery

WORKDIR /home/osquery/
# Execute install script
RUN /bin/bash -c './install_ubuntu_16_04.sh'

# Tell ld where to find libbroker
RUN sudo 

# Set run script
CMD /bin/bash -c './run.sh'
