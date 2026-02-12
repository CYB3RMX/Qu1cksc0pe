from io import BytesIO
import os
import re
import time
import shutil
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
    docker = None

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
        self.image_tag = "qu1cksc0pe_territory:latest"
        self.last_error = None
        self.container_object = None
        self.docker_client = None
        if docker is not None:
            try:
                self.docker_client = docker.from_env()
            except Exception as exc:
                self.last_error = exc

    def check_existing_environment(self):
        if self.docker_client is None:
            return False
        try:
            _ = self.docker_client.images.get(self.image_tag)
            return True
        except Exception:
            return False
        
    def setup_docker_environment(self):
        if self.docker_client is None:
            return False
        print(f"\n{infoS} Creating analysis environment...")
        # Prepare dockerfile object as BytesIO object
        dockerfile_bytes = BytesIO(dockerfile_content.encode('utf-8'))

        # Create new image
        try:
            image, logs = self.docker_client.images.build(
                fileobj=dockerfile_bytes,
                tag=self.image_tag,
                rm=True,
                forcerm=True
            )
            print(f"{infoS} Docker image has been created successfully")
            return True
        except Exception as e:
            self.last_error = e
            return False

    def startup_analysis_environment(self):
        try:
            if self.docker_client is None:
                return None
            # Check analysis environment
            if self.check_existing_environment():

                # Transfer target binary into the analysis environment
                self.container_object = self.docker_client.containers.run(
                    self.image_tag,
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
                if not self.setup_docker_environment():
                    return None
                # Transfer target binary into the analysis environment
                self.container_object = self.docker_client.containers.run(
                    self.image_tag,
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
        except Exception as exc:
            self.last_error = exc
            return None

    def _docker_error_is_permission(self):
        msg = str(self.last_error or "").lower()
        return ("permission denied" in msg) or ("error while fetching server api version" in msg)

    def _qemu_candidates(self):
        mt = str(self.machine_type or "").lower()
        mapping = {
            "x86_64": ["x86_64", "x64"],
            "i386": ["i386", "i686"],
            "i686": ["i686", "i386"],
            "aarch64": ["aarch64", "arm64"],
            "arm64": ["aarch64", "arm64"],
            "arm": ["arm"],
            "mips": ["mips"],
            "mipsel": ["mipsel"],
            "ppc64": ["ppc64", "powerpc64"],
            "riscv64": ["riscv64"],
        }
        archs = mapping.get(mt, [mt]) if mt else []
        bins = []
        for a in archs:
            bins.append(f"qemu-{a}-static")
            bins.append(f"qemu-{a}")
        # De-dup preserving order
        uniq = []
        seen = set()
        for b in bins:
            if b and b not in seen:
                uniq.append(b)
                seen.add(b)
        return uniq

    def _perform_docker_cli_fallback(self):
        """
        Fallback to Docker CLI when docker-py SDK cannot talk to daemon
        (common with rootless Docker/context/socket differences).
        """
        docker_bin = shutil.which("docker")
        if docker_bin is None:
            return False

        print(f"{infoS} Trying Docker CLI fallback...")
        container_name = f"qu1cksc0pe_emul_{os.getpid()}_{int(time.time())}"
        run_ok = False
        try:
            # Ensure image exists
            insp = subprocess.run(
                [docker_bin, "image", "inspect", self.image_tag],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            if insp.returncode != 0:
                print(f"{infoS} Creating analysis environment via Docker CLI...")
                bld = subprocess.run(
                    [docker_bin, "build", "-t", self.image_tag, "-"],
                    input=dockerfile_content,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                if bld.returncode != 0:
                    self.last_error = RuntimeError((bld.stdout or "").strip()[:600])
                    return False

            runp = subprocess.run(
                [
                    docker_bin, "run", "-d",
                    "--name", container_name,
                    "--network", "none",
                    "--cap-drop", "ALL",
                    "--security-opt", "no-new-privileges=true",
                    "--pids-limit", "128",
                    "--memory", "512m",
                    "--cpus", "0.5",
                    self.image_tag, "tail", "-f", "/dev/null",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            if runp.returncode != 0:
                self.last_error = RuntimeError((runp.stdout or "").strip()[:600])
                return False
            run_ok = True

            cp = subprocess.run(
                [docker_bin, "cp", self.target_abs_path, f"{container_name}:/analysis/{self.target_basename}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            if cp.returncode != 0:
                self.last_error = RuntimeError((cp.stdout or "").strip()[:600])
                return False

            print(f"\n{infoS} Executing the target binary...")
            qemu_in_container = f"qemu-{self.machine_type.lower()}-static"
            exe = subprocess.run(
                [docker_bin, "exec", container_name, qemu_in_container, "-strace", f"/analysis/{self.target_basename}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=180,
            )
            output = exe.stdout or ""
            if output.strip():
                self.strace_parser(output)
            else:
                print(f"{errorS} Emulation completed but no syscall trace output was captured.")
            return True
        except Exception as exc:
            self.last_error = exc
            return False
        finally:
            if run_ok:
                print(f"\n{infoS} Cleaning the analysis environment. Please wait...")
            try:
                subprocess.run([docker_bin, "rm", "-f", container_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            except Exception:
                pass

    def _perform_host_fallback(self):
        """
        Best-effort local fallback when Docker is unavailable (e.g., non-root user
        without docker-group access). Requires qemu-user on host.
        """
        qemu_bin = None
        for cand in self._qemu_candidates():
            path = shutil.which(cand)
            if path:
                qemu_bin = path
                break

        if qemu_bin is None:
            print(f"{errorS} Docker unavailable and no suitable qemu binary found on host.")
            print(f"{infoS} Install qemu-user/qemu-user-static or grant Docker access.")
            return False

        print(f"\n{infoS} Docker unavailable. Falling back to host emulation via: [bold green]{qemu_bin}[white]")
        try:
            result_buffer = subprocess.run(
                [qemu_bin, "-strace", self.target_abs_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=180,
            )
            output = result_buffer.stdout or ""
            if output.strip():
                self.strace_parser(output)
            else:
                print(f"{errorS} Emulation completed but no syscall trace output was captured.")
            return True
        except Exception as exc:
            print(f"{errorS} Host fallback emulation failed: {exc}")
            return False

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
            try:
                print(f"\n{infoS} Executing the target binary...")
                result_buffer = self.container_object.exec_run(f"qemu-{self.machine_type.lower()}-static -strace /analysis/{self.target_basename}")
                if result_buffer.output != b"":
                    self.strace_parser(result_buffer.output.decode())
            finally:
                # Cleanup
                print(f"\n{infoS} Cleaning the analysis environment. Please wait...")
                try:
                    self.container_object.stop()
                except Exception:
                    pass
                try:
                    self.container_object.remove()
                except Exception:
                    pass
            return

        # Docker SDK path failed; try Docker CLI fallback first.
        if self._docker_error_is_permission():
            print(f"{infoS} Docker SDK cannot access daemon in current context. Trying Docker CLI fallback...")
        elif self.last_error is not None:
            print(f"{infoS} Docker SDK emulation unavailable ({self.last_error}). Trying Docker CLI fallback...")

        if self._perform_docker_cli_fallback():
            return

        # Docker path failed; provide actionable message and try host fallback.
        if self._docker_error_is_permission():
            print(f"{errorS} Docker permission denied for current user.")
            print(f"{infoS} Add your user to docker group or use sudo for Docker-based emulation.")
        elif self.last_error is not None:
            print(f"{errorS} Docker-based emulation is unavailable: {self.last_error}")

        self._perform_host_fallback()
