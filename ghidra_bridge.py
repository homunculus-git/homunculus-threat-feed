import hashlib
import http.server
import os
import shutil
import socketserver
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

PORT = 9999
SANDBOX_DIR = os.path.expanduser("~/homunculus/homunculus-threat-feed/samples")
PROJECT_FILE = os.path.expanduser("~/homunculus/homunculus-threat-feed/Threat Lab.gpr")
GHIDRA_BINARY = "/usr/bin/ghidra"

DOWNLOAD_SOCKET_TIMEOUT = 300
DOWNLOAD_TOTAL_TIMEOUT = 1800
DOWNLOAD_CHUNK_SIZE = 4096
DOWNLOAD_MAX_ATTEMPTS = 3
DOWNLOAD_RETRY_DELAYS = (15, 30)

ACTIVE_DOWNLOADS = set()
ACTIVE_DOWNLOADS_LOCK = threading.Lock()

os.makedirs(SANDBOX_DIR, exist_ok=True)


def notify(env, title, message):
    subprocess.Popen(
        ["notify-send", title, message],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def refang_url(url):
    return (
        url.replace("hxxps://", "https://")
        .replace("hxxp://", "http://")
        .replace("[.]", ".")
    )


def safe_filename(target_url, sha256):
    parsed = urllib.parse.urlparse(target_url)
    base_name = os.path.basename(parsed.path) if parsed.path else ""

    if (
        not base_name
        or len(base_name) > 100
        or base_name in {".", ".."}
    ):
        base_name = f"sample_{sha256[:8]}.bin" if sha256 else "malware_payload.bin"

    cleaned = "".join(
        character
        for character in base_name
        if character.isalnum() or character in {".", "_", "-"}
    )

    return cleaned or (
        f"sample_{sha256[:8]}.bin" if sha256 else "malware_payload.bin"
    )


def get_file_type(path):
    try:
        result = subprocess.run(
            ["file", "--brief", path],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        return result.stdout.strip() or "Unknown file type"
    except Exception:
        return "Unknown file type"


def create_download_key(target_url, sha256):
    material = f"{target_url}|{sha256}".encode("utf-8", errors="replace")
    return hashlib.sha256(material).hexdigest()


class GhidraBridgeHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        if parsed.path != "/triage":
            self.send_response(404)
            self.end_headers()
            return

        target_url = params.get("target", [""])[0]
        sha256 = params.get("hash", [""])[0]

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        response_html = f"""
        <!DOCTYPE html>
        <html><head><title>Ghidra Lab Dispatcher</title></head>
        <body style="font-family:monospace;background:#11111b;color:#cdd6f4;padding:30px;text-align:center;">
        <h2 style="color:#89b4fa;">⚡ Acquisition dispatched</h2>
        <p>Target: <code>{target_url or sha256}</code></p>
        <p style="color:#a6e3a1;">A complete sample will open in Ghidra only after acquisition succeeds.</p>
        <script>setTimeout(() => window.close(), 2000);</script>
        </body></html>
        """
        self.wfile.write(response_html.encode("utf-8"))

        thread = threading.Thread(
            target=self.launch_lab,
            args=(target_url, sha256),
            daemon=True,
        )
        thread.start()

    def launch_lab(self, target_url, sha256):
        env = os.environ.copy()
        if "DISPLAY" not in env:
            env["DISPLAY"] = ":0"

        if not os.path.isfile(GHIDRA_BINARY) or not os.access(GHIDRA_BINARY, os.X_OK):
            print("[!] Ghidra executable was not found or is not executable.", flush=True)
            notify(env, "⚠ Ghidra Lab", "Ghidra is not installed or not executable")
            return

        if not target_url:
            self.open_ghidra(env)
            return

        real_url = refang_url(target_url)
        download_key = create_download_key(real_url, sha256)

        with ACTIVE_DOWNLOADS_LOCK:
            if download_key in ACTIVE_DOWNLOADS:
                print(f"[*] Download already in progress: {real_url}", flush=True)
                notify(env, "ℹ Ghidra Lab", "Payload download already in progress")
                return
            ACTIVE_DOWNLOADS.add(download_key)

        try:
            base_name = safe_filename(real_url, sha256)
            sample_path = os.path.join(SANDBOX_DIR, base_name)
            part_path = f"{sample_path}.part"

            download_completed, total_bytes = self.download_payload(
                real_url=real_url,
                sample_path=sample_path,
                part_path=part_path,
                env=env,
            )

            if not download_completed:
                print(
                    "[*] Ghidra not launched because payload download did not complete.",
                    flush=True,
                )
                return

            file_type = get_file_type(sample_path)
            print(f"[*] Downloaded file type: {file_type}", flush=True)

            notify(
                env,
                "⚡ Ghidra Lab",
                f"Payload saved: {base_name} ({total_bytes} bytes)",
            )

            self.open_ghidra(env)

        finally:
            with ACTIVE_DOWNLOADS_LOCK:
                ACTIVE_DOWNLOADS.discard(download_key)

    def download_payload(self, real_url, sample_path, part_path, env):
        started_at = time.monotonic()
        last_error = None

        for attempt in range(1, DOWNLOAD_MAX_ATTEMPTS + 1):
            if time.monotonic() - started_at > DOWNLOAD_TOTAL_TIMEOUT:
                break

            existing_bytes = 0
            if os.path.exists(part_path):
                existing_bytes = os.path.getsize(part_path)

            headers = {
                "User-Agent": "Wget/1.21",
                "Accept-Encoding": "identity",
            }

            requested_resume = existing_bytes > 0
            if requested_resume:
                headers["Range"] = f"bytes={existing_bytes}-"

            print(
                f"[*] Download attempt {attempt}/{DOWNLOAD_MAX_ATTEMPTS}: {real_url}",
                flush=True,
            )

            if requested_resume:
                print(
                    f"[*] Requesting resume from byte {existing_bytes}.",
                    flush=True,
                )

            try:
                request = urllib.request.Request(real_url, headers=headers)

                with urllib.request.urlopen(
                    request,
                    timeout=DOWNLOAD_SOCKET_TIMEOUT,
                ) as response:
                    response_status = getattr(response, "status", response.getcode())

                    if requested_resume and response_status != 206:
                        print(
                            "[*] Server did not honour Range resume; restarting download from zero.",
                            flush=True,
                        )
                        existing_bytes = 0
                        with open(part_path, "wb"):
                            pass

                    content_length = response.headers.get("Content-Length")
                    content_range = response.headers.get("Content-Range", "")

                    expected_total = None
                    if response_status == 206 and "/" in content_range:
                        total_text = content_range.rsplit("/", 1)[1]
                        if total_text.isdigit():
                            expected_total = int(total_text)
                    elif content_length and content_length.isdigit():
                        expected_total = existing_bytes + int(content_length)

                    if expected_total is not None:
                        print(
                            f"[*] Expected payload size: {expected_total} bytes "
                            f"({expected_total / 1024:.1f} KiB)",
                            flush=True,
                        )
                    else:
                        print(
                            "[*] Server did not provide a usable total size; "
                            "completion cannot be size-verified.",
                            flush=True,
                        )

                    total_bytes = existing_bytes
                    next_progress_percent = (
                        min(100, ((total_bytes * 100) // expected_total // 10 + 1) * 10)
                        if expected_total
                        else None
                    )

                    mode = "ab" if existing_bytes > 0 and response_status == 206 else "wb"

                    with open(part_path, mode) as output_file:
                        while True:
                            if time.monotonic() - started_at > DOWNLOAD_TOTAL_TIMEOUT:
                                raise TimeoutError(
                                    "download exceeded the 30-minute total limit"
                                )

                            chunk = response.read(DOWNLOAD_CHUNK_SIZE)
                            if not chunk:
                                break

                            output_file.write(chunk)
                            output_file.flush()
                            total_bytes += len(chunk)

                            if expected_total and next_progress_percent is not None:
                                percent = min(
                                    100,
                                    int((total_bytes * 100) / expected_total),
                                )

                                while (
                                    percent >= next_progress_percent
                                    and next_progress_percent <= 100
                                ):
                                    print(
                                        f"[*] Download progress: "
                                        f"{next_progress_percent}% "
                                        f"({total_bytes} of {expected_total} bytes)",
                                        flush=True,
                                    )
                                    next_progress_percent += 10

                if total_bytes == 0:
                    raise RuntimeError("server returned an empty response")

                if expected_total is None:
                    raise RuntimeError(
                        "cannot verify full download because server did not provide a total size"
                    )

                if total_bytes != expected_total:
                    raise RuntimeError(
                        f"incomplete download: received {total_bytes} "
                        f"of {expected_total} bytes"
                    )

                os.replace(part_path, sample_path)

                print(
                    f"[+] Downloaded {total_bytes} bytes to {sample_path}",
                    flush=True,
                )
                return True, total_bytes

            except urllib.error.HTTPError as error:
                last_error = f"HTTP {error.code}: {error.reason}"
                print(f"[!] Payload server returned {last_error}", flush=True)

                if error.code in {404, 410}:
                    break

            except urllib.error.URLError as error:
                reason = getattr(error, "reason", error)
                last_error = f"unreachable: {reason}"
                print(f"[!] Payload server unreachable: {reason}", flush=True)

            except TimeoutError as error:
                current_bytes = (
                    os.path.getsize(part_path)
                    if os.path.exists(part_path)
                    else 0
                )
                last_error = f"timed out after {current_bytes} bytes: {error}"
                print(f"[!] Payload download {last_error}", flush=True)

            except Exception as error:
                current_bytes = (
                    os.path.getsize(part_path)
                    if os.path.exists(part_path)
                    else 0
                )
                last_error = f"failed after {current_bytes} bytes: {error}"
                print(f"[!] Payload download {last_error}", flush=True)

            if attempt < DOWNLOAD_MAX_ATTEMPTS:
                delay = DOWNLOAD_RETRY_DELAYS[attempt - 1]
                remaining = DOWNLOAD_TOTAL_TIMEOUT - (time.monotonic() - started_at)

                if remaining <= delay:
                    break

                print(
                    f"[*] Retrying in {delay} seconds; partial file is retained.",
                    flush=True,
                )
                time.sleep(delay)

        current_bytes = os.path.getsize(part_path) if os.path.exists(part_path) else 0
        message = (
            f"Payload acquisition failed after {current_bytes} bytes"
            if current_bytes
            else "Payload acquisition failed"
        )

        print(
            f"[!] {message}. Last error: {last_error or 'unknown error'}",
            flush=True,
        )
        notify(env, "⚠ Ghidra Lab", message)
        return False, current_bytes

    def open_ghidra(self, env):
        command = [GHIDRA_BINARY]
        if os.path.exists(PROJECT_FILE):
            command.append(PROJECT_FILE)

        subprocess.Popen(command, env=env)
        time.sleep(1)
        subprocess.Popen(["xdg-open", SANDBOX_DIR], env=env)


class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


with ReusableTCPServer(("127.0.0.1", PORT), GhidraBridgeHandler) as httpd:
    print(
        f"[*] Ghidra Local Bridge listening on http://127.0.0.1:{PORT}",
        flush=True,
    )
    httpd.serve_forever()
