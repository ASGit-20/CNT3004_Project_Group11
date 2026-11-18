"""
client.py
CNT3004 - Socket-Based Networked File Sharing Cloud Server

Client-side application for:
    connect/authenticate
    upload
    download
    delete
    dir
    subfolder create/delete

Protocol:
    Every control message is a length-prefixed JSON object.
    File data is transferred as length-prefixed binary chunks.

Expected server responses/requests are documented in the methods below.
The client never sends a plaintext password. Authentication uses a nonce
challenge and HMAC-SHA256:

    proof = HMAC-SHA256(key=SHA256(password), msg=server_nonce)

The server must implement the same protocol for this client to connect.
"""

import argparse
import ssl
import hashlib
import hmac
import json
import os
import socket
import struct
import sys
import time
from pathlib import Path
from typing import Any, Optional


DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1 MiB
MAX_JSON_MESSAGE = 1024 * 1024
SOCKET_TIMEOUT = 30.0


class ProtocolError(Exception):
    """Raised when the server sends an invalid protocol message."""


class FileTransferClient:
    def __init__(
        self,
        server_ip: str,
        port: int,
        username: str,
        password: str,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        timeout: float = SOCKET_TIMEOUT,
    ):
        self.server_ip = server_ip
        self.port = port
        self.username = username
        self.password = password
        self.chunk_size = chunk_size
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None

    # ------------------------------------------------------------
    # Connection / framing
    # ------------------------------------------------------------

    def connect(self) -> None:
        """Connect to the server and complete challenge-response auth."""
        if self.sock is not None:
            self.close()

        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(self.timeout)

        context = ssl.create_default_context(
            cafile = 'server.crt'
        )
        sock = context.wrap_socket(
            raw_sock,
            server_hostname=self.server_ip
        )

        sock.connect((self.server_ip, self.port))
        self.sock = sock


        self._send_json(
            {
                "command": "LOGIN",
                "username": 'fern',
                "password": 'hello123'
            }
        )
        # Receive authentication challenge
        response = self._recv_json()

        if response.get("status") != "SUCCESS":
            raise ProtocolError(
                f"Expected SUCCESS challenge, got: {response}"
            )

        print(f"Connected to {self.server_ip}:{self.port}")
        print(f"Authenticated as {self.username}")

    def close(self) -> None:
        """Close the TCP connection."""
        if self.sock is not None:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            finally:
                self.sock.close()
                self.sock = None

    def _require_connection(self) -> socket.socket:
        if self.sock is None:
            raise ConnectionError("Not connected to a server.")
        return self.sock

    def _send_frame(self, payload: bytes) -> None:
        sock = self._require_connection()

        if len(payload) > MAX_JSON_MESSAGE:
            raise ProtocolError("Control message is too large.")

        header = struct.pack("!I", len(payload))
        sock.sendall(header + payload)

    def _recv_exact(self, size: int) -> bytes:
        sock = self._require_connection()
        data = bytearray()

        while len(data) < size:
            chunk = sock.recv(size - len(data))
            if not chunk:
                raise ConnectionError("Server closed the connection unexpectedly.")
            data.extend(chunk)

        return bytes(data)

    def _recv_frame(self) -> bytes:
        header = self._recv_exact(4)
        (size,) = struct.unpack("!I", header)

        if size > MAX_JSON_MESSAGE:
            raise ProtocolError(f"Frame too large: {size} bytes.")

        return self._recv_exact(size)

    def _send_json(self, message: dict[str, Any]) -> None:
        payload = json.dumps(message, separators=(",", ":")).encode("utf-8")
        self._send_frame(payload)

    def _recv_json(self) -> dict[str, Any]:
        payload = self._recv_frame()

        try:
            message = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProtocolError("Server sent invalid JSON.") from exc

        if not isinstance(message, dict):
            raise ProtocolError("Server JSON message must be an object.")

        return message

    def _send_data(self, data: bytes) -> None:
        """Send one binary data frame."""
        sock = self._require_connection()
        sock.sendall(data)

    def _recv_data(self, size: int) -> bytes:
        """Receive raw binary file data."""
        sock = self._require_connection()
        return sock.recv(size)

    # ------------------------------------------------------------
    # File operations
    # ------------------------------------------------------------

    def upload(self, local_path: str, remote_path: Optional[str] = None) -> None:
        """Upload a local file to the server."""
        path = Path(local_path)

        if not path.is_file():
            raise FileNotFoundError(f"Local file does not exist: {path}")

        remote = remote_path or path.name
        file_size = path.stat().st_size

        start = time.perf_counter()

        self._send_json(
            {
                "command": "UPLOAD",
                "path": remote,
                "size": file_size,
                "filename": path.name,
            }
        )

        response = self._recv_json()

        if response.get("status") == "EXISTS":
            answer = input(
                f"'{remote}' already exists on the server. Overwrite? [y/N]: "
            ).strip().lower()

            if answer not in ("y", "yes"):
                self._send_json({"command": "CANCELED"})
                print("Upload cancelled.")
                return

            self._send_json({"command": "OVERWRITE"})
            response = self._recv_json()

        if response.get("status") != "READY":
            raise RuntimeError(
                response.get("message")
            )

        sent = 0

        with path.open("rb") as file:
            while True:
                chunk = file.read(self.chunk_size)
                if not chunk:
                    break

                self._send_data(chunk)
                sent += len(chunk)

                self._print_progress("Uploading", sent, file_size)


        result = self._recv_json()
        elapsed = time.perf_counter() - start

        if result.get("status") != "SUCCESS":
            raise RuntimeError(result.get("message", "Upload failed."))

        rate = self._rate_mb_s(sent, elapsed)
        print(f"\nUpload complete: {sent / (1024 * 1024):.2f} MB")
        print(f"Time: {elapsed:.3f}s | Rate: {rate:.2f} MB/s")

    def download(self, remote_path: str, local_path: Optional[str] = None) -> None:
        """
        Download a file from the server.

        If a partial file named '<local>.part' exists, the client requests
        a resume from its current size. The server must support:
            {"command":"download","path":...,"offset":...}
        and continue from that byte offset.
        """
        destination = Path(local_path or Path(remote_path).name)
        partial = Path(str(destination) + ".part")

        existing_size = partial.stat().st_size if partial.exists() else 0
        start = time.perf_counter()

        self._send_json(
            {
                "command": "DOWNLOAD",
                "filename": remote_path,
                "offset": existing_size,
            }
        )

        response = self._recv_json()

        if response.get("status") == "ERROR":
            raise FileNotFoundError(response.get("message"))

        if response.get("status") != "READY":
            raise RuntimeError(
                response.get("message", "Server did not accept the download.")
            )

        total_size = int(response.get("size", 0))
        offset = int(response.get("offset", existing_size))
        sha256_expected = response.get("sha256")
        chunk_size = response.get("chunk_size")

        # If the server rejects the requested resume offset, restart safely.
        if offset != existing_size:
            print(
                f"Server requested offset {offset}; local partial file is "
                f"{existing_size} bytes."
            )
            partial.unlink(missing_ok=True)
            existing_size = 0

            self._send_json(
                {
                    "command": "DOWNLOAD",
                    "path": remote_path,
                    "offset": 0,
                }
            )
            response = self._recv_json()

            if response.get("status") != "READY":
                raise RuntimeError(
                    response.get("message", "Download restart was rejected.")
                )

            total_size = int(response.get("size", total_size))
            offset = int(response.get("offset", 0))
            sha256_expected = response.get("sha256")

        mode = "ab" if offset > 0 else "wb"
        received = offset

        with partial.open(mode) as file:
            while received < total_size:
                amount = min(chunk_size, total_size - received)
                data = self._recv_data(amount)

                if not data:
                    raise ConnectionError("Server disconnected during download.")

                file.write(data)
                received += len(data)

                self._print_progress("Downloading", received, total_size)

        self._send_json(
            {
                "command": "download_complete",
                "path": remote_path,
                "size": received,
            }
        )

        result = self._recv_json()

        if result.get("status") != "SUCCESS":
            raise RuntimeError(
                result.get("message", "Server rejected download completion.")
            )

        # Verify SHA-256 if the server supplied one.
        if sha256_expected:
            actual_hash = self._sha256_file(partial)

            if not hmac.compare_digest(actual_hash, sha256_expected):
                raise RuntimeError(
                    "SHA-256 verification failed. The downloaded file is corrupted."
                )

            print("\nSHA-256 verified.")

        partial.replace(destination)

        elapsed = time.perf_counter() - start
        transferred = max(total_size - offset, 0)
        rate = self._rate_mb_s(transferred, elapsed)

        print(f"\nDownload complete: {destination}")
        print(f"Size: {total_size / (1024 * 1024):.2f} MB")
        print(f"Time: {elapsed:.3f}s | Rate: {rate:.2f} MB/s")

    def delete(self, remote_path: str) -> None:
        """Delete a file on the server."""
        self._send_json({"command": "DELETE", "filename": remote_path})

        response = self._recv_json()

        if response.get("status") != "SUCCESS":
            raise RuntimeError(response.get("message", "Delete failed."))

        print(response.get("message", f"Deleted: {remote_path}"))

    def directory(self, remote_path: str = ".") -> None:
        """List files and subdirectories in a server directory."""
        self._send_json({"command": "DIR", "path": remote_path})

        response = self._recv_json()

        if response.get("status") != "SUCCESS":
            raise RuntimeError(response.get("message", "Directory request failed."))

        entries = response.get("entries", [])

        if not entries:
            print("(directory is empty)")
            return

        print(f"\nDirectory: {remote_path}")
        print("-" * 60)

        for entry in entries:
            if isinstance(entry, dict):
                name = entry.get("name", "")
                kind = entry.get("type", "file")
                size = entry.get("size", "")

                if kind == "directory":
                    print(f"[DIR]  {name}")
                else:
                    if size != "":
                        print(f"[FILE] {name} ({size} bytes)")
                    else:
                        print(f"[FILE] {name}")
            else:
                print(entry)

    def subfolder(self, action: str, remote_path: str) -> None:
        """Create or delete a server-side subfolder."""
        if action not in ("create", "delete"):
            raise ValueError("Subfolder action must be 'create' or 'delete'.")

        self._send_json(
            {
                "command": "SUBFOLDER",
                "action": action,
                "path": remote_path,
            }
        )

        response = self._recv_json()

        if response.get("status") != "SUCCESS":
            raise RuntimeError(
                response.get("message", f"Subfolder {action} failed.")
            )

        print(response.get("message", f"Subfolder {action}: {remote_path}"))

    # ------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------

    @staticmethod
    def _sha256_file(path: Path) -> str:
        digest = hashlib.sha256()

        with path.open("rb") as file:
            while True:
                chunk = file.read(DEFAULT_CHUNK_SIZE)
                if not chunk:
                    break
                digest.update(chunk)

        return digest.hexdigest()

    @staticmethod
    def _rate_mb_s(byte_count: int, seconds: float) -> float:
        if seconds <= 0:
            return 0.0
        return (byte_count / (1024 * 1024)) / seconds

    @staticmethod
    def _print_progress(label: str, current: int, total: int) -> None:
        if total <= 0:
            print(f"\r{label}: {current} bytes", end="", flush=True)
            return

        percent = min(100.0, current * 100.0 / total)
        mb_current = current / (1024 * 1024)
        mb_total = total / (1024 * 1024)

        print(
            f"\r{label}: {percent:6.2f}% "
            f"({mb_current:.2f}/{mb_total:.2f} MB)",
            end="",
            flush=True,
        )


def interactive_mode(client: FileTransferClient) -> None:
    """
    Run the client UI in the format demonstrated in the project help file.

    Required menu:
        1. Upload
        2. Download
        3. Delete
        4. Subfolder Create
        5. Subfolder Delete
        6. Dir
        7. Disconnect

    The project reference expects progress, transfer time, speed, and clear
    success/error feedback. The actual transfer methods above already collect
    those metrics.
    """

    print("\n" + "=" * 56)
    print("              FILE SHARING CLIENT v1.0")
    print("=" * 56)

    while True:
        print("\n----------- COMMAND MENU -----------")
        print("1. Upload")
        print("2. Download")
        print("3. Delete")
        print("4. Subfolder Create")
        print("5. Subfolder Delete")
        print("6. Dir")
        print("7. Disconnect")
        print("------------------------------------")

        try:
            choice = input("> ").strip()

            if choice == "1":
                local = input("Enter local filename/path: ").strip()

                if not local:
                    print("[ERROR] A local filename is required.")
                    continue

                remote = input(
                    "Enter server filename/path "
                    f"(press Enter to use '{Path(local).name}'): "
                ).strip()

                client.upload(local, remote or None)

            elif choice == "2":
                remote = input("Enter server filename/path: ").strip()

                if not remote:
                    print("[ERROR] A server filename is required.")
                    continue

                local = input(
                    "Enter local filename/path "
                    f"(press Enter to use '{Path(remote).name}'): "
                ).strip()

                client.download(remote, local or None)

            elif choice == "3":
                remote = input("Enter server filename/path to delete: ").strip()

                if not remote:
                    print("[ERROR] A server filename is required.")
                    continue

                client.delete(remote)

            elif choice == "4":
                remote = input("Enter subfolder path to create: ").strip()

                if not remote:
                    print("[ERROR] A folder path is required.")
                    continue

                client.subfolder("create", remote)

            elif choice == "5":
                remote = input("Enter subfolder path to delete: ").strip()

                if not remote:
                    print("[ERROR] A folder path is required.")
                    continue

                client.subfolder("delete", remote)

            elif choice == "6":
                remote = input(
                    "Enter server directory path "
                    "(press Enter for root): "
                ).strip()

                client.directory(remote or ".")

            elif choice == "7":
                print("[OK] Disconnected from server.")
                break

            else:
                print("[ERROR] Invalid command. Please select 1-7.")

        except (ConnectionError, OSError, RuntimeError, ValueError) as exc:
            print(f"[ERROR] {exc}")

    print("Client session ended.")



def main() -> None:
    #parser = argparse.ArgumentParser(
        #description="CNT3004 networked file-sharing client"
    #)
    #parser.add_argument("--server", required=True, help="Server IP address")
    #parser.add_argument("--port", type=int, required=True, help="Server TCP port")
    #parser.add_argument("--username", required=True, help="Username")
    #parser.add_argument(
        #"--password",
        #help="Password. If omitted, it will be entered without echo.",
    #)
    #parser.add_argument(
        #"--chunk-size",
        #type=int,
        #default=DEFAULT_CHUNK_SIZE,
        #help="Transfer chunk size in bytes (default: 1048576)",
    #)
#
    #args = parser.parse_args()
#
    #if args.chunk_size <= 0:
        #parser.error("--chunk-size must be greater than zero.")
#
    #password = args.password
#
    #if password is None:
        #import getpass
        #password = getpass.getpass("Password: ")

    client = FileTransferClient(
        server_ip= '172.20.5.200',
        port= 5000,
        username= 'fern',
        password= 'hello123'
    )

    try:
        client.connect()
        interactive_mode(client)
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
    except (ConnectionError, PermissionError, ProtocolError, OSError, RuntimeError) as exc:
        print(f"Fatal error: {exc}")
        sys.exit(1)
    finally:
        client.close()


if __name__ == "__main__":
    main()
