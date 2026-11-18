"""
Commands the server understands:
    UPLOAD@name@size        client sends a file to the server
    DOWNLOAD@name           client gets a file from the server
    DELETE@name             delete a file
    DIR                     list files and subfolders (with size and type)
    SUBFOLDER_CREATE@path   make a subfolder
    SUBFOLDER_DELETE@path   remove an EMPTY subfolder
    LOGOUT                  disconnect
"""

import os
import socket
import threading
import time

# ------------------------------------------------------------ settings
IP = "192.168.254.146"
PORT = 4450
ADDR = (IP, PORT)
SIZE = 1024          # how many bytes we read at once for a short command
CHUNK = 4096         # how many bytes we read/send at once for file data
FORMAT = "utf-8"     # how text is turned into bytes (sockets only send bytes)
SERVER_PATH = "server"                  # folder where all uploaded files live
os.makedirs(SERVER_PATH, exist_ok=True)  # create it if it does not exist yet

# ------------------------------------------------- shared data (all threads)
# Every client runs in its own thread, but all threads share these two lines.
# busy_files = files that are being uploaded/downloaded/deleted RIGHT NOW.
# busy_lock  = makes sure only one thread changes busy_files at a time.
busy_files = set()
busy_lock = threading.Lock()

# File extensions used to decide the file type shown in DIR.
TEXT_EXT = {".txt", ".md", ".csv", ".log", ".py"}
VIDEO_EXT = {".mp4", ".mov", ".avi", ".mkv"}
AUDIO_EXT = {".wav", ".mp3", ".flac", ".aac"}


# ---------------------------------------------------------- helper functions
def get_type(filename):
    """Return 'text', 'video', 'audio' or 'other' based on the file extension."""
    ext = os.path.splitext(filename)[1].lower()    # "notes.TXT" -> ".txt"
    if ext in TEXT_EXT:
        return "text"
    if ext in VIDEO_EXT:
        return "video"
    if ext in AUDIO_EXT:
        return "audio"
    return "other"


def safe_path(rel_path):
    """
    Turn a name from the client into a full path INSIDE the server folder.
    Returns None if the name is unsafe, for example "../../secret.txt", which
    would let a client reach files outside the storage folder.
    """
    full = os.path.realpath(os.path.join(SERVER_PATH, rel_path))
    root = os.path.realpath(SERVER_PATH)
    if full == root or not full.startswith(root + os.sep):
        return None
    return full


def claim(path):
    """
    Mark a file as busy before touching it.
    Returns True if we got it, False if another client is already using it.
    This is how DELETE knows a file is "currently being processed".
    """
    with busy_lock:
        if path in busy_files:
            return False
        busy_files.add(path)
        return True


def release(path):
    """Mark the file as free again. Always call this when finished (use finally)."""
    with busy_lock:
        busy_files.discard(path)


# ------------------------------------------------------- one client's session
def handle_client(conn, addr):
    """
    Runs in its own thread for each connected client.
    conn = the socket used to talk to THIS client only.
    addr = the client's (ip, port).
    """

    print(f"[NEW CONNECTION] {addr} connected.")

    try:
        conn.send("OK@Welcome to the server\n".encode(FORMAT))

        # Keep reading commands until the client logs out or disconnects.
        while True:
            raw = conn.recv(SIZE)
            if not raw:                  # empty = the client closed the connection
                break

            # "UPLOAD@a.txt@100" -> ["UPLOAD", "a.txt", "100"]
            data = raw.decode(FORMAT).strip().split("@")
            cmd = data[0].upper()

            send_data = "OK@"            # default reply, sent at the very bottom

            # RULE used in every command below:
            #   success                 -> send_data += "message\n"   (sent at the bottom)
            #   error, or own reply     -> conn.send(...) then "continue"
            #                              ("continue" skips the send at the bottom)

            # -------------------------------------------------- LOGOUT
            if cmd == "LOGOUT":
                break

            elif cmd == "TASK":
                send_data += "LOGOUT from the server.\n"

            # -------------------------------------------------- UPLOAD
            # Client -> server.  UPLOAD@filename@filesize
            # Steps: check name -> (ask to overwrite?) -> READY -> receive bytes.
            elif cmd == "UPLOAD":
                if len(data) < 3:
                    conn.send("ERROR@Usage: UPLOAD@filename@filesize\n".encode(FORMAT))
                    continue

                filename = data[1]
                path = safe_path(filename)
                try:
                    filesize = int(data[2])      # arrives as text, so convert to a number
                except ValueError:
                    filesize = -1

                # Reject bad requests before accepting any file data.
                if path is None or filesize < 0:
                    conn.send("ERROR@Invalid filename or file size\n".encode(FORMAT))
                    continue
                if os.path.isdir(path):
                    conn.send("ERROR@A folder with that name exists\n".encode(FORMAT))
                    continue
                if not os.path.isdir(os.path.dirname(path)):
                    conn.send("ERROR@Target folder does not exist\n".encode(FORMAT))
                    continue
                if not claim(path):              # someone else is using this file
                    conn.send("ERROR@File is currently being processed\n".encode(FORMAT))
                    continue

                print(f"UPLOAD {filename}")
                tmp_path = path + ".part"        # data goes here first (see below)
                received = 0
                completed = False
                start = time.perf_counter()

                try:
                    # File already there? Ask the client whether to overwrite it.
                    if os.path.exists(path):
                        conn.send("EXISTS@File exists. Overwrite? (y/n)\n".encode(FORMAT))
                        raw = conn.recv(SIZE)    # wait for the client's y/n
                        if not raw:
                            raise ConnectionError("client disconnected")
                        answer = raw.decode(FORMAT).strip().split("@")[0].lower()
                        if answer != "y":
                            conn.send("CANCELLED@Upload cancelled\n".encode(FORMAT))
                            continue             # finally block below still runs

                    # Tell the client to start sending. The client waits for this
                    # so file bytes are never mixed up with commands.
                    conn.send("READY@Send the file\n".encode(FORMAT))
                    print("Receiving file...")

                    # Write into a temporary ".part" file. If the upload breaks
                    # halfway, the real file is never damaged.
                    with open(tmp_path, "wb") as f:      # "wb" = write raw bytes
                        while received < filesize:
                            # Ask for at most CHUNK bytes, never more than what is left,
                            # so we do not read into the client's next command.
                            chunk = conn.recv(min(CHUNK, filesize - received))
                            if not chunk:        # client disconnected early
                                break
                            f.write(chunk)       # raw bytes, do NOT decode them
                            received += len(chunk)

                    completed = (received == filesize)
                finally:
                    # Runs no matter what (success, cancel, error, disconnect).
                    if completed:
                        os.replace(tmp_path, path)   # swap .part in as the real file
                    elif os.path.exists(tmp_path):
                        os.remove(tmp_path)          # incomplete: throw the .part away
                    release(path)                    # file is free again

                elapsed = max(time.perf_counter() - start, 1e-9)   # avoid dividing by 0
                if completed:
                    mb = filesize / 1_000_000
                    print(f"Upload complete.\nUpload: {mb:.2f} MB / {elapsed:.2f} s\nRate: {mb / elapsed:.2f} MB/s\n")
                    send_data += "Upload complete\n"
                else:
                    print("Upload failed: connection lost.\n")
                    send_data = "ERROR@Upload incomplete\n"

            # -------------------------------------------------- DOWNLOAD
            # Server -> client.  DOWNLOAD@filename
            # Reply: "OK@filesize\n" and then exactly filesize raw bytes.
            elif cmd == "DOWNLOAD":
                if len(data) < 2:
                    conn.send("ERROR@Usage: DOWNLOAD@filename\n".encode(FORMAT))
                    continue

                filename = data[1]
                path = safe_path(filename)

                if path is None or not os.path.isfile(path):   # must be a real file
                    conn.send("ERROR@File does not exist\n".encode(FORMAT))
                    continue
                if not claim(path):
                    conn.send("ERROR@File is currently being processed\n".encode(FORMAT))
                    continue

                print(f"DOWNLOAD {filename}")
                download_size = 0

                try:
                    filesize = os.path.getsize(path)   # the server knows the size
                    # The client needs the size so it knows when the file ends.
                    conn.send(f"OK@{filesize}\n".encode(FORMAT))
                    print("Sending file...")
                    with open(path, "rb") as f:        # "rb" = read raw bytes
                        while chunk := f.read(CHUNK):  # read the file piece by piece
                            conn.sendall(chunk)        # sendall = send every byte
                            download_size += len(chunk)
                finally:
                    release(path)

                print(f"Download complete.\nDownload: {download_size / 1_000_000:.2f} MB\n")
                continue    # the file bytes were the reply; do not send "OK@" after them

            # -------------------------------------------------- DELETE
            # DELETE@filename   (error if missing or currently in use)
            elif cmd == "DELETE":
                if len(data) < 2:
                    conn.send("ERROR@Usage: DELETE@filename\n".encode(FORMAT))
                    continue

                filename = data[1]
                print(f"DELETE {filename}")
                path = safe_path(filename)

                if path is None or not os.path.isfile(path):
                    conn.send("ERROR@File does not exist\n".encode(FORMAT))
                    print("[ERROR] File does not exist.\n")
                    continue
                if not claim(path):              # being uploaded/downloaded right now
                    conn.send("ERROR@File is currently being processed\n".encode(FORMAT))
                    print("[ERROR] File is currently being processed.\n")
                    continue

                try:
                    os.remove(path)
                    send_data += "File deleted\n"
                    print("File deleted.\n")
                except OSError:
                    send_data = "ERROR@Could not delete file\n"
                finally:
                    release(path)

            # -------------------------------------------------- DIR
            # List every file and subfolder with size and type.
            # Reply: "OK@length\n" and then the list as text.
            elif cmd == "DIR":
                print("Directory requested.")
                lines = []                       # one text line per file or folder

                # os.walk visits SERVER_PATH and then every subfolder inside it.
                for root, dirs, files in os.walk(SERVER_PATH):
                    rel = os.path.relpath(root, SERVER_PATH)   # path without the server folder
                    if rel == ".":
                        rel = ""

                    for d in sorted(dirs):
                        lines.append(f"[DIR]  {os.path.join(rel, d)}/")

                    for f in sorted(files):
                        if f.endswith(".part"):  # hide uploads that are still in progress
                            continue
                        size = os.path.getsize(os.path.join(root, f))
                        lines.append(f"[FILE] {os.path.join(rel, f)} | {size} bytes | {get_type(f)}")

                listing = "\n".join(lines) if lines else "(empty)"
                payload = listing.encode(FORMAT)
                # Send the length first so the client knows how many bytes to read.
                conn.send(f"OK@{len(payload)}\n".encode(FORMAT))
                conn.sendall(payload)
                print("Directory list sent.\n")
                continue

            # -------------------------------------------------- SUBFOLDER_CREATE
            # SUBFOLDER_CREATE@path   e.g. docs  or  docs/week1
            elif cmd == "SUBFOLDER_CREATE":
                if len(data) < 2:
                    conn.send("ERROR@Usage: SUBFOLDER_CREATE@path\n".encode(FORMAT))
                    continue

                path = safe_path(data[1])

                if path is None:
                    conn.send("ERROR@Invalid path\n".encode(FORMAT))
                    continue
                if os.path.exists(path):
                    conn.send("ERROR@Already exists\n".encode(FORMAT))
                    continue

                os.makedirs(path)                # also creates missing parent folders
                send_data += "Folder created\n"
                print(f"Folder created: {data[1]}\n")

            # -------------------------------------------------- SUBFOLDER_DELETE
            # SUBFOLDER_DELETE@path   (only works on an EMPTY folder)
            elif cmd == "SUBFOLDER_DELETE":
                if len(data) < 2:
                    conn.send("ERROR@Usage: SUBFOLDER_DELETE@path\n".encode(FORMAT))
                    continue

                path = safe_path(data[1])

                if path is None:
                    conn.send("ERROR@Invalid path\n".encode(FORMAT))
                    continue
                if not os.path.isdir(path):
                    conn.send("ERROR@Subfolder does not exist\n".encode(FORMAT))
                    continue

                # Hold the lock so no transfer can start between the checks and the delete.
                with busy_lock:
                    if any(p.startswith(path + os.sep) for p in busy_files):
                        send_data = "ERROR@A file inside is being processed\n"
                    elif os.listdir(path):       # a non-empty list means it has contents
                        send_data = "ERROR@Subfolder is not empty\n"
                    else:
                        try:
                            os.rmdir(path)       # rmdir only works on empty folders
                            send_data += "Folder deleted\n"
                            print(f"Folder deleted: {data[1]}\n")
                        except OSError:
                            send_data = "ERROR@Could not delete folder\n"

            # -------------------------------------------------- anything else
            else:
                send_data = "ERROR@Unknown command\n"

            # Reply for every command that did not send its own reply above.
            conn.send(send_data.encode(FORMAT))

    except (ConnectionError, OSError) as e:
        # The client vanished (closed the window, lost Wi-Fi...). Not a crash.
        print(f"[CONNECTION ERROR] {addr}: {e}")
    finally:
        conn.close()
        print(f"[DISCONNECTED] {addr}")


# ------------------------------------------------------------ start the server
def main():
    print("Starting the server")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    # IPv4 + TCP
    # Lets you restart the server right away without "address already in use".
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(ADDR)           # attach the socket to our IP and port
    server.listen()             # start waiting for clients
    print(f"server is listening on {IP}: {PORT}")
    while True:
        conn, addr = server.accept()      # waits here until a client connects
        # One thread per client so clients do not have to wait for each other.
        # daemon=True: threads stop automatically when the server is closed.
        thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        thread.start()


if __name__ == "__main__":
    main()
