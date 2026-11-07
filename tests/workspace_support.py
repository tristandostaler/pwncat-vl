"""Disposable loopback SSH/SFTP fixture for workspace integration tests only."""

import errno
import fcntl
import os
import pty
import shlex
import socket
import struct
import subprocess
import termios
import threading
from pathlib import Path

import paramiko


class TestFilesystem(paramiko.SFTPServerInterface):
    def __init__(self, server, *args, root, **kwargs):
        super().__init__(server, *args, **kwargs)
        self.root = Path(root).resolve()

    def path(self, path):
        result = Path(path).resolve()
        if result != self.root and self.root not in result.parents:
            raise PermissionError(errno.EACCES, "Outside test filesystem")
        return str(result)

    def _call(self, operation, *args):
        try:
            return operation(*args)
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno)

    def stat(self, path):
        return self._call(
            lambda: paramiko.SFTPAttributes.from_stat(os.stat(self.path(path)))
        )

    def lstat(self, path):
        return self._call(
            lambda: paramiko.SFTPAttributes.from_stat(os.lstat(self.path(path)))
        )

    def list_folder(self, path):
        def run():
            results = []
            for entry in os.scandir(self.path(path)):
                attrs = paramiko.SFTPAttributes.from_stat(
                    entry.stat(follow_symlinks=False)
                )
                attrs.filename = entry.name
                results.append(attrs)
            return results

        return self._call(run)

    def open(self, path, flags, attr):
        def run():
            fd = os.open(self.path(path), flags, attr.st_mode or 0o600)
            stream = os.fdopen(
                fd,
                "r+b" if flags & os.O_RDWR else "wb" if flags & os.O_WRONLY else "rb",
                buffering=0,
            )
            handle = paramiko.SFTPHandle(flags)
            handle.readfile = handle.writefile = stream
            return handle

        return self._call(run)

    def mkdir(self, path, attr):
        return self._call(
            lambda: os.mkdir(self.path(path), attr.st_mode or 0o700) or paramiko.SFTP_OK
        )

    def chattr(self, path, attr):
        return self._call(
            lambda: os.chmod(self.path(path), attr.st_mode) or paramiko.SFTP_OK
        )

    def remove(self, path):
        return self._call(lambda: os.unlink(self.path(path)) or paramiko.SFTP_OK)

    def rmdir(self, path):
        return self._call(lambda: os.rmdir(self.path(path)) or paramiko.SFTP_OK)

    def rename(self, source, destination):
        def run():
            if os.path.exists(self.path(destination)):
                raise FileExistsError(errno.EEXIST, "Exists")
            os.rename(self.path(source), self.path(destination))
            return paramiko.SFTP_OK

        return self._call(run)

    def posix_rename(self, source, destination):
        return self._call(
            lambda: (
                os.replace(self.path(source), self.path(destination))
                or paramiko.SFTP_OK
            )
        )


class TestSSH(paramiko.ServerInterface):
    def __init__(self, owner):
        self.owner = owner
        self.terminals = {}

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        self.terminals[channel.get_id()] = (width, height)
        return True

    def check_auth_publickey(self, username, key):
        return (
            paramiko.AUTH_SUCCESSFUL
            if username == "test" and key == self.owner.key
            else paramiko.AUTH_FAILED
        )

    def get_allowed_auths(self, username):
        return (
            "publickey,password"
            if getattr(self.owner, "password", None)
            else "publickey"
        )

    def check_auth_password(self, username, password):
        return (
            paramiko.AUTH_SUCCESSFUL
            if username == "test" and password == getattr(self.owner, "password", None)
            else paramiko.AUTH_FAILED
        )

    def check_channel_request(self, kind, chanid):
        return (
            paramiko.OPEN_SUCCEEDED
            if kind == "session"
            else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        )

    def check_channel_exec_request(self, channel, command):
        # Only the workspace's tmux executable and fixed preflight are accepted.
        argv = shlex.split(command.decode())
        if not argv or argv[0] not in ("sh", self.owner.tmux):
            return False
        terminal = self.terminals.get(channel.get_id())
        thread = threading.Thread(
            target=self.owner.run, args=(channel, argv, terminal), daemon=True
        )
        thread.start()
        return True


class LoopbackSSH:
    def __init__(self, home, tmux):
        self.home, self.tmux = str(home), tmux
        self.key = paramiko.RSAKey.generate(2048)
        self.host_key = paramiko.RSAKey.generate(2048)
        self.identity = str(home / "test-key")
        self.known_hosts = str(home / "known_hosts")
        self.key.write_private_key_file(self.identity)
        os.chmod(self.identity, 0o600)
        self.socket = socket.socket()
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(5)
        self.socket.settimeout(0.2)
        self.port = self.socket.getsockname()[1]
        Path(self.known_hosts).write_text(
            f"[127.0.0.1]:{self.port} {self.host_key.get_name()} {self.host_key.get_base64()}\n"
        )
        self.stopped = threading.Event()
        self.transports = []
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def accept(self):
        while not self.stopped.is_set():
            try:
                client, _ = self.socket.accept()
            except socket.timeout:  # noqa: UP041 - Python 3.9 compatibility
                continue
            except OSError:
                return
            transport = paramiko.Transport(client)
            self.transports.append(transport)
            transport.add_server_key(self.host_key)
            transport.set_subsystem_handler(
                "sftp", paramiko.SFTPServer, TestFilesystem, root=self.home
            )
            try:
                transport.start_server(server=TestSSH(self))
            except (EOFError, paramiko.SSHException):
                transport.close()

    def run(self, channel, argv, terminal=None):
        env = {
            "HOME": self.home,
            "PATH": os.path.dirname(self.tmux) + ":/usr/bin:/bin",
            "TERM": "xterm-256color",
            "LC_ALL": "en_US.UTF-8",
        }
        if terminal:
            self.run_terminal(channel, argv, env, terminal)
            return
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.home,
            env=env,
        )

        def input_loop():
            try:
                while True:
                    data = channel.recv(65536)
                    if not data:
                        break
                    proc.stdin.write(data)
                    proc.stdin.flush()
            except (OSError, EOFError):
                pass
            finally:
                proc.stdin.close()

        def output_loop(stream, send):
            try:
                while True:
                    data = os.read(stream.fileno(), 65536)
                    if not data:
                        break
                    send(data)
            except (OSError, EOFError):
                pass
            finally:
                stream.close()

        threading.Thread(target=input_loop, daemon=True).start()
        readers = [
            threading.Thread(
                target=output_loop, args=(proc.stdout, channel.sendall), daemon=True
            ),
            threading.Thread(
                target=output_loop,
                args=(proc.stderr, channel.sendall_stderr),
                daemon=True,
            ),
        ]
        for thread in readers:
            thread.start()
        status = proc.wait()
        for thread in readers:
            thread.join(timeout=1)
        try:
            channel.send_exit_status(status)
        except (OSError, EOFError):
            pass
        channel.close()

    def run_terminal(self, channel, argv, env, dimensions):
        master, slave = pty.openpty()
        width, height = dimensions
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", height, width, 0, 0))
        proc = subprocess.Popen(
            argv,
            stdin=slave,
            stdout=slave,
            stderr=slave,
            cwd=self.home,
            env=env,
            start_new_session=True,
        )
        os.close(slave)

        def input_loop():
            try:
                while True:
                    data = channel.recv(4096)
                    if not data:
                        break
                    os.write(master, data)
            except (OSError, EOFError):
                pass
            finally:
                if proc.poll() is None:
                    proc.terminate()  # Only this disposable display client, not its tmux server.

        threading.Thread(target=input_loop, daemon=True).start()
        try:
            while True:
                data = os.read(master, 65536)
                if not data:
                    break
                channel.sendall(data)
        except (OSError, EOFError):
            pass
        finally:
            os.close(master)
            if proc.poll() is None:
                proc.terminate()
            status = proc.wait(timeout=5)
            try:
                channel.send_exit_status(status)
            except (OSError, EOFError):
                pass
            channel.close()

    def close(self):
        self.stopped.set()
        self.socket.close()
        for transport in self.transports:
            transport.close()
        self.thread.join(timeout=2)
