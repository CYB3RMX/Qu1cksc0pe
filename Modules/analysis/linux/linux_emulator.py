from io import BytesIO
import os
import re
import subprocess

# Testing rich existence
try:
    from rich import print
    from rich.table import Table
except:
    print("Error: >rich< module not found.")

try:
    from colorama import Fore, Style
except:
    print("Error: >colorama< module not found.")

try:
    import docker
except:
    print("Error: >docker< module not found.")

# Colors
red = Fore.LIGHTRED_EX
cyan = Fore.LIGHTCYAN_EX
white = Style.RESET_ALL
green = Fore.LIGHTGREEN_EX

# Legends
infoC = f"{cyan}[{red}*{cyan}]{white}"
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
foundS = f"[bold cyan][[bold red]+[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"

# Create docker env for analysis
dockerfile_content = '''
FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y qemu-user-static strace file libc6-mips-cross libc6-mipsel-cross && rm -rf /var/lib/apt/lists/* && apt-get clean
RUN useradd -r -u 10000 -s /usr/sbin/nologin -d /tmp sandbox \
    && mkdir -p /analysis \
    && chown sandbox:sandbox /analysis \
    && chmod 700 /analysis
RUN rm -f /usr/bin/wget /usr/bin/curl /bin/nc /bin/netcat /usr/bin/perl \
    /usr/bin/ssh /usr/bin/scp /usr/bin/sftp /usr/bin/ftp

WORKDIR /analysis
USER sandbox
'''

class Linxcution:
    def __init__(self, target_binary_file, machine_type):
        self.target_binary_file = target_binary_file
        self.machine_type = machine_type
        self.target_abs_path = os.path.abspath(self.target_binary_file)
        self.target_basename = os.path.basename(self.target_abs_path)
        self.docker_client = docker.from_env()

    def check_existing_environment(self):
        try:
            _ = self.docker_client.images.get("qu1cksc0pe_territory:latest")
            return True
        except:
            return False
        
    def setup_docker_environment(self):
        print(f"\n{infoS} Creating analysis environment...")
        # Prepare dockerfile object as BytesIO object
        dockerfile_bytes = BytesIO(dockerfile_content.encode('utf-8'))

        # Create new image
        try:
            image, logs = self.docker_client.images.build(
                fileobj=dockerfile_bytes,
                tag="qu1cksc0pe_territory:latest",
                rm=True,
                forcerm=True
            )
            print(f"{infoS} Docker image has been created successfully")
        except Exception as e:
            print(e)

    def startup_analysis_environment(self):
        try:
            # Check analysis environment
            if self.check_existing_environment():

                # Transfer target binary into the analysis environment
                self.container_object = self.docker_client.containers.run(
                    "qu1cksc0pe_territory:latest",
                    command="tail -f /dev/null",
                    detach=True,
                    working_dir="/analysis",
                    privileged=False,
                    network_mode="none",
                    cap_drop=["ALL"],
                    security_opt=["no-new-privileges=true"],
                    read_only=False,
                    pids_limit=128,
                    mem_limit="512m",
                    nano_cpus=500_000_000,
                    ulimits=[
                        docker.types.Ulimit(name="core", soft=0, hard=0),
                        docker.types.Ulimit(name="nofile", soft=1024, hard=1024),
                        docker.types.Ulimit(name="fsize", soft=100*1024*1024, hard=100*1024*1024),
                    ]
                )
                _ = subprocess.run(f"chmod +x {self.target_abs_path} && docker cp {self.target_abs_path} {self.container_object.id}:/analysis/{self.target_basename}", shell=True, stdout=subprocess.PIPE)
            else:
                self.setup_docker_environment()
                # Transfer target binary into the analysis environment
                self.container_object = self.docker_client.containers.run(
                    "qu1cksc0pe_territory:latest",
                    command="tail -f /dev/null",
                    detach=True,
                    working_dir="/analysis",
                    privileged=False,
                    network_mode="none",
                    cap_drop=["ALL"],
                    security_opt=["no-new-privileges=true"],
                    read_only=False,
                    pids_limit=128,
                    mem_limit="512m",
                    nano_cpus=500_000_000,
                    ulimits=[
                        docker.types.Ulimit(name="core", soft=0, hard=0),
                        docker.types.Ulimit(name="nofile", soft=1024, hard=1024),
                        docker.types.Ulimit(name="fsize", soft=100*1024*1024, hard=100*1024*1024),
                    ]
                )
                _ = subprocess.run(f"docker cp {self.target_abs_path} {self.container_object.id}:/analysis/{self.target_basename}", shell=True, stdout=subprocess.PIPE)
            return True
        except:
            return None

    def strace_parser(self, buffer):
        syscall_re = re.compile(r"""
                                ^\s*\d+\s+        # PID
                                (?P<name>[a-zA-Z0-9_]+)   # syscall name
                                \((?P<args>.*)\)  # args
                                \s+=              # return value
                                """, re.VERBOSE)
        parsed = []
        for line in buffer.splitlines():
            m = syscall_re.match(line)
            if m:
                name = m.group("name")
                args = m.group("args")
                parsed.append((name, args))

        table = Table()
        table.add_column("[bold green]Syscall", justify="center")
        table.add_column("[bold green]Args")
        for name, args in parsed:
            table.add_row(name, args)
        print(table)

    def perform_analysis(self):
        if self.startup_analysis_environment():
            print(f"\n{infoS} Executing the target binary...")
            result_buffer = self.container_object.exec_run(f"qemu-{self.machine_type.lower()}-static -strace /analysis/{self.target_basename}")
            if result_buffer.output != b"":
                self.strace_parser(result_buffer.output.decode())

            # Cleanup
            print(f"\n{infoS} Cleaning the analysis environment. Please wait...")
            self.container_object.stop()
            self.container_object.remove()