# Create environment
FROM ubuntu:latest
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Istanbul

# Gather dependencies
RUN apt update && apt install -y curl wget git binutils sudo unzip python3 python3-pip libimage-exiftool-perl mono-complete default-jre
RUN pip3 install setuptools wheel pythonnet pycryptodome python-magic

# Install application
WORKDIR /app
COPY . .

# Configuration
RUN chmod +x qu1cksc0pe.py setup.sh
RUN ln -s /root /home/root
RUN ./setup.sh
RUN wget https://raw.githubusercontent.com/CYB3RMX/MalwareHashDB/main/HashDB -O /home/root/sc0pe_Base/HashDB

# Cleanup
RUN apt clean

# RE-Enter app directory
WORKDIR /app
ENTRYPOINT ["/app/qu1cksc0pe.py"]