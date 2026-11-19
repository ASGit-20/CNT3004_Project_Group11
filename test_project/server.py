"""
CNT3004 - Socket-Based Networked File Sharing Cloud Server

Overview:
- TCP connection protected by TLS
- Control messages are JSON with a 4-byte length prefix
- File contents are sent as raw bytes in chunks after the server replies READY
- Each client connection is handled by its own thread

This file is designed to work with a client that follows the protocol described
in the project documentation/comments below.
"""


import argparse
import hashlib
import hmac
import json
import os
import secrets
import socket
import ssl
import struct
import threading
import time
from pathlib import Path
from pathlib import PurePosixPath

from network_stats import NetworkStats



#  Configuration  ===========================================


IP = "172.20.5.200"
PORT = 5000

STORAGE_DIR = Path("server_storage")
USER_LOGIN_FILE = Path("users.json")
CERT_FILE = Path("server.crt")
KEY_FILE = Path("server.key")

CHUNK_SIZE = 64 * 1024             # 64 KB at a time
MAX_CONTROL_MESSAGE = 1024 * 1024 # 1 MB maximum JSON control message
PBKDF2_ITERATIONS = 600_000

# Supported extensions are used to create logical server-side file names.
# Example: a .txt upload becomes TS001.txt.
FILE_PREFIXES = {
    ".txt": "TS", ".md": "TS", ".csv": "TS", ".log": "TS",
    ".mp3": "AS", ".wav": "AS", ".aac": "AS", ".flac": "AS",
    ".mp4": "VS", ".mov": "VS", ".avi": "VS", ".mkv": "VS",
    ".png": "IM", ".jpg": "IM", ".jpeg": "IM", ".gif": "IM",
    ".pdf": "DO", ".doc": "DO", ".docx": "DO",
}



#  Shared Server Data  ===========================================


stats = NetworkStats()
storage_lock = threading.Lock()
active_transfers = set()
active_transfers_lock = threading.Lock()

# Connection logging state.
client_counter = 0
active_clients = 0
client_counter_lock = threading.Lock()
active_clients_lock = threading.Lock()
client_log_context = threading.local()


def log_thread(message, blank_line=False):
    """Print a message with the current client's thread label.

    Set blank_line=True to separate this message from the previous log group
    with exactly one empty line.
    """
    if blank_line:
        print()

    thread_id = getattr(client_log_context, "thread_id", None)
    if thread_id is None:
        print(message)
    else:
        print(f"[THREAD-{thread_id}] {message}")


def format_megabytes(byte_count):
    """Format a byte count as MB for transfer log messages."""
    return byte_count / (1024 * 1024)



#  Message Framing  ===========================================


def send_message(sock, message):
    """Send one JSON message preceded by its 4-byte length."""
    data = json.dumps(message).encode("utf-8")

    if len(data) > MAX_CONTROL_MESSAGE:
        raise ValueError("Control message is too large.")

    header = struct.pack("!I", len(data))
    sock.sendall(header + data)


def receive_exactly(sock, amount):
    """Read exactly 'amount' bytes, unless the connection closes."""
    received = bytearray()

    while len(received) < amount:
        chunk = sock.recv(min(CHUNK_SIZE, amount - len(received)))

        if not chunk:
            raise ConnectionError("The other computer disconnected.")

        received.extend(chunk)

    return bytes(received)


def receive_message(sock):
    """Receive and decode one length-prefixed JSON message."""
    header = receive_exactly(sock, 4)
    message_length = struct.unpack("!I", header)[0]

    if message_length <= 0 or message_length > MAX_CONTROL_MESSAGE:
        raise ValueError("Invalid control message length.")

    data = receive_exactly(sock, message_length)
    message = json.loads(data.decode("utf-8"))

    if not isinstance(message, dict):
        raise ValueError("A control message must be a JSON object.")

    return message



#  User Authentication  ===========================================


def hash_password(password, salt=None):
    """Create a salted PBKDF2 password hash."""
    if salt is None:
        salt = secrets.token_bytes(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS
    )

    return salt.hex(), password_hash.hex()


def verify_password(password, stored_salt, stored_hash):
    """Check a submitted password against its stored salted hash."""
    salt = bytes.fromhex(stored_salt)
    expected_hash = bytes.fromhex(stored_hash)

    actual_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS
    )

    return hmac.compare_digest(actual_hash, expected_hash)


def load_users():
    if not USER_LOGIN_FILE.exists():
        raise FileNotFoundError(
            "users.json was not found. Create an account with "
            "'python server.py --create-user USERNAME'."
        )

    with USER_LOGIN_FILE.open("r", encoding="utf-8") as file:
        users = json.load(file)

    if not isinstance(users, dict):
        raise ValueError("users.json must contain a JSON object.")

    return users


def create_user(username):
    """Interactively create a user record without saving plaintext password."""
    import getpass

    username = username.strip()

    if not username or len(username) > 64:
        raise ValueError("Username must contain 1 to 64 characters.")

    users = {}
    if USER_LOGIN_FILE.exists():
        with USER_LOGIN_FILE.open("r", encoding="utf-8") as file:
            users = json.load(file)

    if username in users:
        raise ValueError("That username already exists.")

    password = getpass.getpass("New password: ")
    confirmation = getpass.getpass("Confirm password: ")

    if len(password) < 8:
        raise ValueError("Use a password with at least 8 characters.")

    if password != confirmation:
        raise ValueError("The passwords do not match.")

    salt, password_hash = hash_password(password)
    users[username] = {
        "salt": salt,
        "password_hash": password_hash,
        "iterations": PBKDF2_ITERATIONS
    }

    with USER_LOGIN_FILE.open("w", encoding="utf-8") as file:
        json.dump(users, file, indent=4)

    try:
        os.chmod(USER_LOGIN_FILE, 0o600)
    except OSError:
        pass

    print(f"[SERVER] Created account for '{username}'.")


def authenticate(message, users):
    """Return True only when the username and password are valid."""
    username = message.get("username")
    password = message.get("password")

    if not isinstance(username, str) or not isinstance(password, str):
        return False

    user_record = users.get(username)
    if not isinstance(user_record, dict):
        return False

    try:
        return verify_password(
            password,
            user_record["salt"],
            user_record["password_hash"]
        )
    except (KeyError, ValueError, TypeError):
        return False



#  File Naming and Safe Path Handling  ===========================================


def safe_original_filename(filename):
    """
    Accept only a plain file name, not a path supplied by a client.
    This prevents names such as ../../important.txt.
    """
    if not isinstance(filename, str) or not filename:
        raise ValueError("A file name is required.")

    if filename in {".", ".."}:
        raise ValueError("Invalid file name.")

    if Path(filename).name != filename:
        raise ValueError("Folder paths are not allowed in file names.")

    if "/" in filename or "\\" in filename or "\x00" in filename:
        raise ValueError("Invalid characters in file name.")

    if len(filename) > 255:
        raise ValueError("File name is too long.")

    return filename



def choose_server_filename(original_filename):
    """Generate a unique logical server file name, such as TS001.txt."""
    extension = Path(original_filename).suffix.lower()
    prefix = FILE_PREFIXES.get(extension, "OT")

    existing_numbers = []

    # Check files in the main directory and all subfolders.
    for path in STORAGE_DIR.rglob("*"):
        if not path.is_file():
            continue

        if path.name.startswith(prefix):
            stem = path.stem
            number_text = stem[len(prefix):]

            if number_text.isdigit():
                existing_numbers.append(int(number_text))

    # Check filenames currently reserved by active uploads.
    with active_transfers_lock:
        for filename in active_transfers:
            active_name = Path(filename).name

            if active_name.startswith(prefix):
                stem = Path(active_name).stem
                number_text = stem[len(prefix):]

                if number_text.isdigit():
                    existing_numbers.append(int(number_text))

    next_number = max(existing_numbers, default=0) + 1

    return f"{prefix}{next_number:03d}{extension}"


def get_storage_path(server_filename):
    """Resolve a server-side name and ensure it stays inside storage."""
    safe_name = safe_original_filename(server_filename)
    path = (STORAGE_DIR / safe_name).resolve()
    storage_root = STORAGE_DIR.resolve()

    if path.parent != storage_root:
        raise ValueError("Invalid server file path.")

    return path


def get_server_storage_path(server_filename):
    if not isinstance(server_filename, str) or not server_filename:
        raise ValueError("Invalid server filename.")

    if "\\" in server_filename or "\x00" in server_filename:
        raise ValueError("Invalid server filename.")

    relative_path = PurePosixPath(server_filename)

    if relative_path.is_absolute() or len(relative_path.parts) not in (1, 2):
        raise ValueError("Invalid server filename.")

    if any(part in {".", ".."} for part in relative_path.parts):
        raise ValueError("Invalid server filename.")

    storage_root = STORAGE_DIR.resolve()
    full_path = (storage_root / Path(*relative_path.parts)).resolve()

    if not full_path.is_relative_to(storage_root):
        raise ValueError("Invalid server filename.")

    return full_path


def file_is_in_use(server_filename):
    with active_transfers_lock:
        return server_filename in active_transfers



#  File Operations  ===========================================


def handle_upload(sock, request, username):
    original_name = safe_original_filename(request.get("filename"))
    remote_path = request.get("path", original_name)
    file_size = request.get("size")

    if not isinstance(file_size, int) or isinstance(file_size, bool) or file_size < 0:
        send_message(sock, {
            "status": "ERROR",
            "message": "Invalid file size."
        })
        return

    max_file_size = 5 * 1024 * 1024 * 1024  # 5 GB

    if file_size > max_file_size:
        send_message(sock, {
            "status": "ERROR",
            "message": "File exceeds the 5 GB limit."
        })
        return

    try:
        # Validate the requested remote path.
        if not isinstance(remote_path, str) or "\\" in remote_path:
            raise ValueError("Invalid upload path.")

        requested_path = PurePosixPath(remote_path)

        if requested_path.is_absolute() or len(requested_path.parts) not in (1, 2):
            raise ValueError("Only one subfolder level is supported.")

        if any(part in {"", ".", ".."} for part in requested_path.parts):
            raise ValueError("Invalid upload path.")

        # The requested filename must match the original filename.
        if requested_path.name != original_name:
            raise ValueError("Upload filename does not match the original filename.")

        # Determine the destination directory.
        if len(requested_path.parts) == 1:
            folder_path = STORAGE_DIR.resolve()
            folder_name = ""
        else:
            folder_name = safe_original_filename(requested_path.parts[0])
            folder_path = (STORAGE_DIR / folder_name).resolve()

            if folder_path.parent != STORAGE_DIR.resolve():
                raise ValueError("Invalid subfolder path.")

            if not folder_path.is_dir():
                raise ValueError("The requested subfolder does not exist.")

        with storage_lock:
            matching_files = []

            # Search metadata in the main directory and subfolders.
            for metadata_path in STORAGE_DIR.rglob("*.meta"):
                try:
                    metadata = json.loads(
                        metadata_path.read_text(encoding="utf-8")
                    )

                    if metadata.get("original_name") == original_name:
                        matching_files.append(metadata_path)

                except (OSError, json.JSONDecodeError):
                    continue

            if matching_files:
                send_message(sock, {
                    "status": "EXISTS",
                    "message": "A file with this original name already exists. Overwrite it?"
                })

                try:
                    decision = receive_message(sock)
                except (ConnectionError, ValueError, json.JSONDecodeError):
                    return

                if decision.get("command") != "OVERWRITE":
                    send_message(sock, {
                        "status": "CANCELLED",
                        "message": "Upload cancelled."
                    })
                    return

                # Remove old matching files after confirmation.
                for metadata_path in matching_files:
                    old_path = metadata_path.resolve().with_suffix("")
                    old_name = old_path.relative_to(
                        STORAGE_DIR.resolve()
                    ).as_posix()

                    if file_is_in_use(old_name):
                        send_message(sock, {
                            "status": "ERROR",
                            "message": "That file is currently being transferred."
                        })
                        return

                    if old_path.exists():
                        old_path.unlink()

                    metadata_path.unlink(missing_ok=True)

            # Generate the server-assigned filename.
            server_filename = choose_server_filename(original_name)

            # Store the generated name relative to STORAGE_DIR.
            if folder_name:
                stored_filename = f"{folder_name}/{server_filename}"
            else:
                stored_filename = server_filename

            final_path = get_server_storage_path(stored_filename)
            temp_path = final_path.with_name(final_path.name + ".part")
            metadata_path = final_path.with_name(final_path.name + ".meta")

            if final_path.exists() or metadata_path.exists():
                raise ValueError("Generated server filename already exists.")

            # Reserve the logical filename during the upload.
            with active_transfers_lock:
                active_transfers.add(stored_filename)

        send_message(sock, {
            "status": "READY",
            "server_filename": stored_filename,
            "chunk_size": CHUNK_SIZE
        })

        log_thread("Receiving file...")
        start_time = time.perf_counter()
        bytes_received = 0
        success = False

        try:
            with temp_path.open("wb") as output_file:
                while bytes_received < file_size:
                    amount = min(CHUNK_SIZE, file_size - bytes_received)
                    chunk = sock.recv(amount)

                    if not chunk:
                        raise ConnectionError("Connection lost during upload.")

                    output_file.write(chunk)
                    bytes_received += len(chunk)

            os.replace(temp_path, final_path)

            metadata = {
                "original_name": original_name,
                "server_filename": stored_filename,
                "uploaded_by": username,
                "size": file_size
            }

            metadata_path.write_text(
                json.dumps(metadata, indent=4),
                encoding="utf-8"
            )

            success = True

            elapsed = time.perf_counter() - start_time
            log_thread("Upload completed.")
            print(
                f"[ANALYSIS] Upload: {format_megabytes(bytes_received):.0f} MB / "
                f"{elapsed:.2f} s"
            )
            rate = format_megabytes(bytes_received) / elapsed if elapsed > 0 else 0
            print(f"[ANALYSIS] Rate: {rate:.2f} MB/s")

            stats.record_transfer(
                direction="upload",
                username=username,
                filename=stored_filename,
                bytes_transferred=bytes_received,
                duration_seconds=elapsed
            )

            send_message(sock, {
                "status": "SUCCESS",
                "message": "Upload completed.",
                "server_filename": stored_filename,
                "bytes_received": bytes_received
            })

        except (OSError, ConnectionError):
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass

            if not success:
                try:
                    final_path.unlink(missing_ok=True)
                    metadata_path.unlink(missing_ok=True)
                except OSError:
                    pass

            raise

        finally:
            with active_transfers_lock:
                active_transfers.discard(stored_filename)

    except ValueError as error:
        send_message(sock, {
            "status": "ERROR",
            "message": str(error)
        })


    except OSError as error:

        print(f"[ERROR] Upload failed: {error}")

        send_message(sock, {

            "status": "ERROR",

            "message": "The server could not save the uploaded file."

        })



def handle_download(sock, request, username):
    original_name = request.get("filename")

    if not isinstance(original_name, str) or not original_name:
        send_message(sock, {
            "status": "ERROR",
            "message": "Invalid filename."
        })
        return

    server_filename = None

    try:
        # Validate the original filename.
        original_name = safe_original_filename(original_name)

        # Find the metadata associated with the original filename.
        matching_metadata = None
        matching_metadata_path = None

        for metadata_path in STORAGE_DIR.rglob("*.meta"):
            try:
                metadata = json.loads(
                    metadata_path.read_text(encoding="utf-8")
                )

                if metadata.get("original_name") == original_name:
                    matching_metadata = metadata
                    matching_metadata_path = metadata_path
                    break

            except (OSError, json.JSONDecodeError):
                continue

        if matching_metadata is None:
            send_message(sock, {
                "status": "ERROR",
                "message": "File metadata does not exist."
            })
            return

        # Retrieve the server-assigned filename from metadata.
        server_filename = matching_metadata.get("server_filename")

        if not isinstance(server_filename, str) or not server_filename:
            raise ValueError("File metadata is invalid.")

        # Resolve the file path, including any subfolder.
        path = get_server_storage_path(server_filename)

        # Verify that the metadata file is located beside the requested file.
        expected_metadata_path = path.with_name(path.name + ".meta")

        if matching_metadata_path.resolve() != expected_metadata_path.resolve():
            raise ValueError("File metadata does not match the requested file.")

        if not path.is_file():
            send_message(sock, {
                "status": "ERROR",
                "message": "File does not exist."
            })
            return

        # Verify that the file size matches its metadata.
        file_size = path.stat().st_size

        if matching_metadata.get("size") != file_size:
            send_message(sock, {
                "status": "ERROR",
                "message": "File size does not match its metadata."
            })
            return

        # Reserve the file while it is being downloaded.
        with active_transfers_lock:
            if server_filename in active_transfers:
                send_message(sock, {
                    "status": "ERROR",
                    "message": "File is currently being transferred."
                })
                return

            active_transfers.add(server_filename)

        log_thread("Sending file...")

        # Calculate SHA-256 before sending the file.
        file_hash = hashlib.sha256()

        with path.open("rb") as file:
            while True:
                chunk = file.read(CHUNK_SIZE)

                if not chunk:
                    break

                file_hash.update(chunk)

        # Tell the client that the file is ready.
        send_message(sock, {
            "status": "READY",
            "size": file_size,
            "sha256": file_hash.hexdigest(),
            "chunk_size": CHUNK_SIZE
        })

        start_time = time.perf_counter()
        bytes_sent = 0

        # Send the raw file data.
        with path.open("rb") as file:
            while True:
                chunk = file.read(CHUNK_SIZE)

                if not chunk:
                    break

                sock.sendall(chunk)
                bytes_sent += len(chunk)

        elapsed = time.perf_counter() - start_time
        log_thread("Download completed.")
        print(f"[ANALYSIS] Download: {format_megabytes(bytes_sent):.0f} MB")

        # Record download statistics.
        stats.record_transfer(
            direction="download",
            username=username,
            filename=server_filename,
            bytes_transferred=bytes_sent,
            duration_seconds=elapsed
        )

        send_message(sock, {
            "status": "SUCCESS",
            "bytes_sent": bytes_sent
        })

    except ValueError as error:
        send_message(sock, {
            "status": "ERROR",
            "message": str(error)
        })

    except OSError as error:
        print(f"[ERROR] Download failed: {error}")

        try:
            send_message(sock, {
                "status": "ERROR",
                "message": "The server could not read the requested file."
            })
        except OSError:
            pass

    finally:
        # Release the file reservation.
        if server_filename is not None:
            with active_transfers_lock:
                active_transfers.discard(server_filename)



def handle_delete(sock, request):
    original_name = request.get("filename")

    if not isinstance(original_name, str) or not original_name:
        send_message(sock, {
            "status": "ERROR",
            "message": "Invalid filename."
        })
        return

    try:
        # Validate the original filename supplied by the client.
        original_name = safe_original_filename(original_name)

        with storage_lock:
            matching_metadata = None
            matching_metadata_path = None

            # Search the root directory and all subfolders.
            for metadata_path in STORAGE_DIR.rglob("*.meta"):
                try:
                    metadata = json.loads(
                        metadata_path.read_text(encoding="utf-8")
                    )

                    if metadata.get("original_name") == original_name:
                        matching_metadata = metadata
                        matching_metadata_path = metadata_path
                        break

                except (OSError, json.JSONDecodeError):
                    continue

            if matching_metadata is None:
                print("[ERROR] File does not exist.")
                send_message(sock, {
                    "status": "ERROR",
                    "message": "File does not exist."
                })
                return

            # Retrieve the server-assigned relative filename.
            server_filename = matching_metadata.get("server_filename")

            if not isinstance(server_filename, str):
                send_message(sock, {
                    "status": "ERROR",
                    "message": "File metadata is invalid."
                })
                return

            # Locate the actual file, including its subfolder.
            path = get_server_storage_path(server_filename)

            if not path.is_file():
                send_message(sock, {
                    "status": "ERROR",
                    "message": "Stored file does not exist."
                })
                return

            # Verify that the metadata belongs to this file.
            expected_metadata_path = path.with_name(
                path.name + ".meta"
            )

            if matching_metadata_path.resolve() != expected_metadata_path.resolve():
                send_message(sock, {
                    "status": "ERROR",
                    "message": "File metadata does not match the stored file."
                })
                return

            # Check whether the file is currently being transferred.
            if file_is_in_use(server_filename):
                send_message(sock, {
                    "status": "ERROR",
                    "message": "File is currently being transferred."
                })
                return

            # Delete the actual file and its associated metadata.
            path.unlink()
            matching_metadata_path.unlink(missing_ok=True)

        send_message(sock, {
            "status": "SUCCESS",
            "message": "File deleted."
        })
        log_thread("File deleted.")

    except ValueError as error:
        send_message(sock, {
            "status": "ERROR",
            "message": str(error)
        })

    except OSError:
        send_message(sock, {
            "status": "ERROR",
            "message": "The server could not delete the file."
        })



def handle_directory(sock, request):
    requested_path = request.get("path", "")

    try:
        # Root directory if no path was provided.
        if requested_path == "":
            folder_path = STORAGE_DIR.resolve()

        else:
            if not isinstance(requested_path, str) or "\\" in requested_path:
                raise ValueError("Invalid directory path.")

            relative_path = PurePosixPath(requested_path)

            if relative_path.is_absolute() or len(relative_path.parts) > 2:
                raise ValueError("Invalid directory path.")

            if any(part in {"", ".", ".."} for part in relative_path.parts):
                raise ValueError("Invalid directory path.")

            folder_path = (
                STORAGE_DIR / Path(*relative_path.parts)
            ).resolve()

        # Prevent access outside the storage directory.
        if not folder_path.is_relative_to(STORAGE_DIR.resolve()):
            raise ValueError("Invalid directory path.")

        if not folder_path.is_dir():
            send_message(sock, {
                "status": "ERROR",
                "message": "Directory does not exist."
            })
            return

        entries = []

        for path in sorted(folder_path.iterdir()):
            if path.name.endswith(".meta") or path.name.endswith(".part"):
                continue

            if path.is_file():
                entries.append({
                    "name": path.name,
                    "type": "file",
                    "size": path.stat().st_size
                })

            elif path.is_dir():
                entries.append({
                    "name": path.name,
                    "type": "directory"
                })

        send_message(sock, {
            "status": "SUCCESS",
            "path": requested_path,
            "entries": entries
        })
        log_thread("Directory list sent.")

    except ValueError as error:
        send_message(sock, {
            "status": "ERROR",
            "message": str(error)
        })

    except OSError:
        send_message(sock, {
            "status": "ERROR",
            "message": "Could not read directory."
        })



def handle_subfolder(sock, request):
    action = request.get("action")
    folder_name = request.get("path")

    try:
        folder_name = safe_original_filename(folder_name)
        folder_path = (STORAGE_DIR / folder_name).resolve()

        if folder_path.parent != STORAGE_DIR.resolve():
            raise ValueError("Only folders directly inside the storage directory are supported.")

        if action == "create":
            folder_path.mkdir(exist_ok=False)
            send_message(sock, {"status": "SUCCESS", "message": "Subfolder created."})
            log_thread("Folder created.")

        elif action == "delete":
            folder_path.rmdir()  # Only succeeds if the folder is empty.
            send_message(sock, {"status": "SUCCESS", "message": "Empty subfolder deleted."})

        else:
            send_message(sock, {"status": "ERROR", "message": "Action must be create or delete."})

    except FileExistsError:
        send_message(sock, {"status": "ERROR", "message": "That folder already exists."})
    except FileNotFoundError:
        send_message(sock, {"status": "ERROR", "message": "That folder does not exist."})
    except OSError:
        send_message(sock, {
            "status": "ERROR",
            "message": "Folder could not be deleted. It may not be empty."
        })
    except ValueError as error:
        send_message(sock, {"status": "ERROR", "message": str(error)})



#  One Client Connection  ===========================================


def handle_client(raw_client_socket, client_address, ssl_context, users):
    """Handle authentication and all requests from one connected client."""
    global client_counter, active_clients
    client_socket = None
    username = None
    counted_as_active = False

    with client_counter_lock:
        client_counter += 1
        thread_id = client_counter

    client_log_context.thread_id = thread_id
    print()
    print(f"[CONNECT] {client_address[0]}:{client_address[1]}")
    log_thread(f"Started for Client {thread_id}")

    try:
        client_socket = ssl_context.wrap_socket(raw_client_socket, server_side=True)
        client_socket.settimeout(300)
        login_request = receive_message(client_socket)

        if login_request.get("command") != "LOGIN" or not authenticate(login_request, users):
            send_message(client_socket, {
                "status": "ERROR",
                "message": "Invalid username or password."
            })
            log_thread("[ERROR] Authentication failed.")
            return

        username = login_request.get("username")
        send_message(client_socket, {"status": "SUCCESS", "message": "Login successful."})
        log_thread(f"[AUTH] {username} authenticated.", blank_line=True)

        with active_clients_lock:
            active_clients += 1
            counted_as_active = True
            print(f"[SERVER] Active clients: {active_clients}")

        while True:
            request = receive_message(client_socket)
            request_start = time.perf_counter()
            command = request.get("command")

            if command == "UPLOAD":
                log_thread(f"UPLOAD {request.get('filename', '')}", blank_line=True)
                handle_upload(client_socket, request, username)

            elif command == "DOWNLOAD":
                log_thread(f"DOWNLOAD {request.get('filename', '')}", blank_line=True)
                handle_download(client_socket, request, username)

            elif command == "DELETE":
                log_thread(f"DELETE {request.get('filename', '')}", blank_line=True)
                handle_delete(client_socket, request)

            elif command == "DIR":
                log_thread("DIR requested.", blank_line=True)
                handle_directory(client_socket, request)

            elif command == "SUBFOLDER":
                action = str(request.get("action", "")).upper()
                folder = request.get("path", "")
                log_thread(f"{action} {folder}", blank_line=True)
                handle_subfolder(client_socket, request)

            elif command == "QUIT":
                send_message(client_socket, {
                    "status": "SUCCESS",
                    "message": "Goodbye."
                })

                response_time = time.perf_counter() - request_start
                stats.record_response(
                    username=username,
                    command=str(command),
                    response_time_seconds=response_time
                )
                break

            else:
                send_message(client_socket, {
                    "status": "ERROR",
                    "message": "Unknown command."
                })
                log_thread("[ERROR] Unknown command.")

            response_time = time.perf_counter() - request_start

            stats.record_response(
                username=username,
                command=str(command),
                response_time_seconds=response_time
            )

    except socket.timeout:
        pass
    except ConnectionError:
        pass
    except ssl.SSLError as error:
        log_thread(f"[ERROR] TLS error: {error}")
    except (ValueError, json.JSONDecodeError) as error:
        log_thread(f"[ERROR] Invalid request: {error}")
        if client_socket:
            try:
                send_message(client_socket, {"status": "ERROR", "message": "Invalid request."})
            except OSError:
                pass
    except OSError as error:
        log_thread(f"[ERROR] Network or file error: {error}")
    finally:
        if client_socket is not None:
            try:
                client_socket.close()
            except OSError:
                pass
        else:
            try:
                raw_client_socket.close()
            except OSError:
                pass

        log_thread("[DISCONNECT] Client disconnected.", blank_line=True)

        if counted_as_active:
            with active_clients_lock:
                active_clients -= 1
                print(f"[SERVER] Active clients: {active_clients}")
                if active_clients == 0:
                    print("[SERVER] Waiting for requests...")

        try:
            del client_log_context.thread_id
        except AttributeError:
            pass



#  Server Startup  ===========================================


def start_server():
    print("FILE SHARING SERVER v1.0\n")
    print("[SERVER] Starting...")

    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    print("[SERVER] Storage initialized.")

    users = load_users()

    if not CERT_FILE.is_file() or not KEY_FILE.is_file():
        raise FileNotFoundError(
            "TLS certificate/key not found. Create server.crt and server.key "
            "before starting the server."
        )

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(certfile=str(CERT_FILE), keyfile=str(KEY_FILE))

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((IP, PORT))
    print(f"[SERVER] IP: {IP}")
    print(f"[SERVER] Port: {PORT}")
    # Network statistics are initialized through NetworkStats.
    print("[ANALYSIS] Monitoring started.")

    server_socket.listen()
    server_socket.settimeout(1.0)
    print("[SERVER] Listening for connections...")

    try:
        while True:
            try:
                raw_client_socket, client_address = server_socket.accept()
            except socket.timeout:
                continue

            client_thread = threading.Thread(
                target=handle_client,
                args=(raw_client_socket, client_address, ssl_context, users),
                daemon=True
            )
            client_thread.start()

    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down...")

    finally:
        server_socket.close()
        stats.save()
        print("[ANALYSIS] Statistics saved.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CNT3004 file-sharing server")
    parser.add_argument(
        "--create-user",
        metavar="USERNAME",
        help="Create a user account, then exit."
    )
    args = parser.parse_args()

    if args.create_user:
        create_user(args.create_user)
    else:
        start_server()