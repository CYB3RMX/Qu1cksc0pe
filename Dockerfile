# Create environment
FROM ubuntu:latest
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Istanbul

# Install application
WORKDIR /app
COPY . .

# Gather dependencies
RUN apt update && \
apt install -y curl wget git binutils sudo unzip python3 python3-pip python3-setuptools python3-wheel python3-pycryptodome python3-magic dos2unix mono-complete default-jre adb && \
apt clean && \
useradd -m -s /bin/bash quickscope

USER quickscope
WORKDIR /home/quickscope

RUN git clone https://github.com/CYB3RMX/Qu1cksc0pe.git app && \
find app -type f -exec dos2unix {} \; && \
cd app && \
# Configuration
chmod 755 qu1cksc0pe.py setup.sh && \
./setup.sh && \
wget https://raw.githubusercontent.com/CYB3RMX/MalwareHashDB/main/HashDB -O /home/quickscope/sc0pe_Base/HashDB

# RE-Enter app directory
WORKDIR /home/quickscope/app
ENTRYPOINT ["/home/quickscope/app/qu1cksc0pe.py"]
