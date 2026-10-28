import os
import sys
import json
import re
import urllib.request
import urllib.parse
import urllib.error
import tempfile
import zipfile
import subprocess
import threading
import logging
import hashlib
import shutil
import posixpath

GITHUB_REPO = "Aleff959/CPUTempMonitor"
API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"

ALLOWED_HOSTS = {
    "github.com",
    "api.github.com",
    "objects.githubusercontent.com",
    "raw.githubusercontent.com",
    "codeload.github.com",
    "release-assets.githubusercontent.com",
}


def _parse_version_tuple(v_str):
    """Parse version string into tuple of ints for comparison, ignoring build/comp and pre-release suffix."""
    s = str(v_str).strip()
    if "|" in s:
        s = s.split("|")[0]
    s = s.strip().lstrip("(").rstrip(")")
    if "(" in s:
        s = s.split("(")[0]
    s = s.strip().lstrip("vV")
    s = re.split(r"[-+~]|(?<=\d)(?:rc|alpha|beta|dev|preview|pre)", s, flags=re.IGNORECASE)[0]
    m = re.findall(r"\d+", s)
    return tuple(int(x) for x in m) if m else (0,)


def _parse_comp_number(text):
    """Extract compilation number from text (e.g. 'Comp. 22' or '(1.5.0 | Comp. 22)' -> 22)."""
    m = re.search(r"comp\.?\s*(\d+)", str(text), re.IGNORECASE)
    return int(m.group(1)) if m else 0


class StrictHTTPSRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Enforces HTTPS and confines redirects strictly to official GitHub domains."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl:
            raise urllib.error.URLError("Redirecionamento com URL vazia bloqueado.")

        parsed = urllib.parse.urlparse(newurl)
        if parsed.scheme.lower() != "https":
            raise urllib.error.URLError(f"Protocolo inseguro bloqueado em redirecionamento: {parsed.scheme}")

        host = (parsed.hostname or "").lower()
        if host not in ALLOWED_HOSTS:
            raise urllib.error.URLError(f"Redirecionamento não autorizado para domínio externo: {host}")

        return super().redirect_request(req, fp, code, msg, headers, newurl)


def is_safe_github_url(url: str, repo: str = GITHUB_REPO) -> bool:
    """Validate that the URL is strictly HTTPS and originates from the official repository."""
    if not url or not isinstance(url, str):
        return False
    try:
        parsed = urllib.parse.urlparse(url.strip())
        if parsed.scheme.lower() != "https":
            return False

        if parsed.port not in (None, 443):
            return False

        if parsed.username or parsed.password:
            return False

        host = (parsed.hostname or "").lower()
        if not host:
            return False

        raw_path = parsed.path or ""
        unquoted = raw_path
        for _ in range(3):
            next_unquoted = urllib.parse.unquote(unquoted)
            if next_unquoted == unquoted:
                break
            unquoted = next_unquoted
        unquoted = unquoted.replace("\\", "/")
        norm_path = posixpath.normpath(unquoted.lower())
        if not norm_path.startswith("/"):
            norm_path = "/" + norm_path

        repo_lower = repo.lower()

        if host == "github.com":
            return norm_path.startswith(f"/{repo_lower}/releases/") or norm_path.startswith(f"/{repo_lower}/archive/")
        elif host == "api.github.com":
            return norm_path.startswith(f"/repos/{repo_lower}/releases")
        elif host in ("raw.githubusercontent.com", "codeload.github.com"):
            return norm_path.startswith(f"/{repo_lower}/")
        elif host == "objects.githubusercontent.com":
            return True
        return False
    except Exception:
        return False


def compute_sha256(filepath: str) -> str:
    """Calculate the SHA-256 hash of a local file in chunks."""
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest().lower()


def parse_hash_from_checksum_file(content: str, target_filename: str) -> str:
    """Extract SHA-256 hash from a checksums file (e.g. SHA256SUMS.txt or filename.sha256)."""
    if not content or not target_filename:
        return ""
    content = content.lstrip("\ufeff")
    target_lower = target_filename.lower()
    for line in content.splitlines():
        line = line.strip().lstrip("\ufeff")
        if not line or line.startswith("#"):
            continue
        parts = line.split(maxsplit=1)
        if len(parts) == 2:
            h, fname = parts[0].strip(), parts[1].strip().lstrip("*").strip()
            if len(h) == 64 and all(c in "0123456789abcdefABCDEF" for c in h):
                fname_clean = fname.replace("\\", "/").split("/")[-1].lower()
                if fname_clean == target_lower:
                    return h.lower()
        if len(line) == 64 and all(c in "0123456789abcdefABCDEF" for c in line):
            return line.lower()
    return ""


def parse_hash_from_body(body: str, target_filename: str) -> str:
    """Extract SHA-256 hash from release body/markdown."""
    if not body:
        return ""
    if target_filename:
        target_esc = re.escape(target_filename)
        # Match target filename followed by hash (supports markdown bold **, backticks `, pipes |)
        m = re.search(rf"[*`_]*{target_esc}[*`_]*\s*[:=\-|]\s*`?([a-fA-F0-9]{{64}})`?", body, re.IGNORECASE)
        if m:
            return m.group(1).lower()
        # Match hash followed by target filename (supports standard sha256 lines and tables)
        m = re.search(rf"`?([a-fA-F0-9]{{64}})`?\s*[:=\-|]?\s+[*`_]*{target_esc}[*`_]*", body, re.IGNORECASE)
        if m:
            return m.group(1).lower()
    # Fallback to generic sha-256 label
    m = re.search(r"(?:sha-?256|hash|checksum)\s*[:=\-|]\s*`?([a-fA-F0-9]{64})`?", body, re.IGNORECASE)
    if m:
        return m.group(1).lower()
    return ""


def _cleanup_dir(directory: str) -> None:
    """Safely delete directory and all its contents."""
    try:
        if directory and os.path.exists(directory):
            shutil.rmtree(directory, ignore_errors=True)
    except Exception as e:
        logging.warning(f"Falha ao limpar diretório temporário {directory}: {e}")


class AppUpdater:
    def __init__(self, current_version="1.5.0", current_comp=23):
        self.current_version = current_version
        self.current_comp = current_comp
        self.update_info = None

    def _get_opener(self):
        return urllib.request.build_opener(StrictHTTPSRedirectHandler())

    def check_for_updates(self):
        """Query GitHub Releases API and compare with local version and comp."""
        try:
            req = urllib.request.Request(
                API_URL,
                headers={
                    "User-Agent": "FulgorPCista-Updater",
                    "Accept": "application/vnd.github.v3+json",
                },
            )
            opener = self._get_opener()
            with opener.open(req, timeout=8.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            tag_name = data.get("tag_name", "").strip()
            release_name = data.get("name", "").strip() or tag_name
            body = data.get("body", "").strip()
            assets = data.get("assets", [])

            remote_ver = tag_name.lstrip("vV")
            remote_comp = _parse_comp_number(release_name) or _parse_comp_number(body)

            curr_ver_tuple = _parse_version_tuple(self.current_version)
            remote_ver_tuple = _parse_version_tuple(remote_ver)

            has_update = False
            if remote_ver_tuple > curr_ver_tuple:
                has_update = True
            elif remote_ver_tuple == curr_ver_tuple:
                if remote_comp > self.current_comp:
                    has_update = True

            # Find best asset to download: prefer standalone .exe, then newest .zip
            chosen_asset = None
            for a in assets:
                name = a.get("name", "").lower()
                if name == "fulgorpcista.exe":
                    chosen_asset = a
                    break
            if not chosen_asset:
                for a in assets:
                    name = a.get("name", "").lower()
                    if name.endswith(".exe"):
                        chosen_asset = a
                        break
            if not chosen_asset:
                zip_assets = [a for a in assets if a.get("name", "").lower().endswith(".zip") and "fulgor" in a.get("name", "").lower()]
                if zip_assets:
                    zip_assets.sort(key=lambda a: (_parse_comp_number(a.get("name", "")), a.get("created_at", "")), reverse=True)
                    chosen_asset = zip_assets[0]

            download_url = chosen_asset.get("browser_download_url") if chosen_asset else None
            asset_name = chosen_asset.get("name") if chosen_asset else None
            asset_size = chosen_asset.get("size", 0) if chosen_asset else 0

            # Identify checksum asset or hash source (Cascade 1: Checksum file)
            checksum_url = None
            for a in assets:
                a_name = a.get("name", "").lower()
                if a_name in ("sha256sums", "sha256sums.txt", "checksums.txt", "hashes.txt"):
                    checksum_url = a.get("browser_download_url")
                    break
                if asset_name and a_name == f"{asset_name.lower()}.sha256":
                    checksum_url = a.get("browser_download_url")
                    break

            # Cascade 1: API asset digest
            expected_sha256 = ""
            if chosen_asset and chosen_asset.get("digest"):
                digest_val = str(chosen_asset["digest"]).strip()
                if digest_val.lower().startswith("sha256:"):
                    expected_sha256 = digest_val.split(":")[-1].lower()

            # Cascade 2: Checksum file from release assets (SHA256SUMS.txt / .sha256)
            if not expected_sha256 and checksum_url and is_safe_github_url(checksum_url):
                try:
                    c_req = urllib.request.Request(checksum_url, headers={"User-Agent": "FulgorPCista-Updater"})
                    with opener.open(c_req, timeout=8.0) as c_resp:
                        c_text = c_resp.read().decode("utf-8", errors="ignore")
                        expected_sha256 = parse_hash_from_checksum_file(c_text, asset_name or "FulgorPCista.exe")
                except Exception as ce:
                    logging.warning(f"Não foi possível obter arquivo de hashes ({checksum_url}): {ce}")

            # Cascade 3: Body markdown fallback
            if not expected_sha256:
                expected_sha256 = parse_hash_from_body(body, asset_name or "FulgorPCista.exe")

            self.update_info = {
                "success": True,
                "has_update": has_update,
                "available": has_update,
                "version": remote_ver,
                "comp": remote_comp,
                "tag_name": tag_name,
                "notes": body,
                "current_version": f"({self.current_version} | Comp. {self.current_comp})",
                "latest_version": tag_name,
                "latest_title": release_name,
                "changelog": body,
                "download_url": download_url,
                "asset_name": asset_name,
                "asset_size_mb": round(asset_size / (1024 * 1024), 1) if asset_size else 0.0,
                "checksum_url": checksum_url,
                "expected_sha256": expected_sha256,
                "expected_hash": expected_sha256,
            }
            return self.update_info

        except urllib.error.HTTPError as e:
            if e.code == 403:
                err_msg = "Limite de requisições do GitHub atingido (Rate limit excedido). Tente novamente mais tarde."
            else:
                err_msg = f"Erro HTTP {e.code} ao consultar GitHub: {e.reason}"
            logging.error(f"Erro ao verificar atualizações: {err_msg}")
            return {
                "success": False,
                "has_update": False,
                "available": False,
                "error": err_msg,
                "current_version": f"({self.current_version} | Comp. {self.current_comp})",
            }
        except Exception as e:
            logging.error(f"Erro inesperado ao verificar atualizações: {e}", exc_info=True)
            return {
                "success": False,
                "has_update": False,
                "available": False,
                "error": str(e),
                "current_version": f"({self.current_version} | Comp. {self.current_comp})",
            }

    def apply_update(self, download_url=None, expected_hash=None):
        """Download new version, validate SHA-256 against official release hash, and apply cleanly."""
        update_dir = os.path.join(tempfile.gettempdir(), "FulgorPCista_Update")
        _cleanup_dir(update_dir)

        url = download_url or (self.update_info.get("download_url") if self.update_info else None)
        if not url:
            return {"success": False, "error": "URL de download não encontrada."}

        # Protocol and domain strict enforcement
        if not is_safe_github_url(url):
            _cleanup_dir(update_dir)
            return {
                "success": False,
                "error": "Violação de segurança: O download foi recusado pois a URL não pertence ao repositório oficial sob HTTPS.",
            }

        opener = self._get_opener()

        try:
            os.makedirs(update_dir, exist_ok=True)

            raw_filename = url.split("?")[0].replace("\\", "/").split("/")[-1]
            filename = os.path.basename(urllib.parse.unquote(raw_filename))
            download_dest = os.path.join(update_dir, filename)
            dest_abs = os.path.abspath(download_dest)
            update_dir_abs = os.path.abspath(update_dir)
            if not dest_abs.startswith(update_dir_abs + os.sep):
                _cleanup_dir(update_dir)
                return {"success": False, "error": "Destino de download inválido ou fora do sandbox temporário."}

            logging.info(f"Baixando atualização segura de {url} para {download_dest}...")
            req = urllib.request.Request(url, headers={"User-Agent": "FulgorPCista-Updater", "Accept": "*/*"})
            with opener.open(req, timeout=45.0) as resp, open(download_dest, "wb") as f:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)

            # Compute actual SHA-256 of downloaded payload
            computed_sha256 = compute_sha256(download_dest)
            logging.info(f"Hash SHA-256 do arquivo baixado ({filename}): {computed_sha256}")

            # Resolve expected SHA-256 in cascade:
            # 1. Parameter or update_info expected_sha256
            target_hash = (expected_hash or (self.update_info.get("expected_sha256") if self.update_info else "") or "").strip().lower()

            # 2. Checksum file from release assets if not yet resolved
            checksum_url = self.update_info.get("checksum_url") if self.update_info else None
            if not target_hash and checksum_url and is_safe_github_url(checksum_url):
                try:
                    c_req = urllib.request.Request(checksum_url, headers={"User-Agent": "FulgorPCista-Updater"})
                    with opener.open(c_req, timeout=15.0) as c_resp:
                        c_text = c_resp.read().decode("utf-8", errors="ignore")
                        target_hash = parse_hash_from_checksum_file(c_text, filename)
                except Exception as ce:
                    logging.warning(f"Não foi possível obter arquivo de hashes ({checksum_url}): {ce}")

            # Cryptographic Integrity Check
            if not target_hash or len(target_hash) != 64:
                _cleanup_dir(update_dir)
                logging.error(f"Atualização abortada: Hash SHA-256 esperado ausente ou inválido ({target_hash}).")
                return {
                    "success": False,
                    "error": (
                        "Atualização abortada por segurança: Nenhum hash SHA-256 oficial válido foi localizado "
                        "para este pacote no GitHub. O arquivo baixado foi descartado."
                    ),
                    "code": "SHA256_MISSING",
                }

            if computed_sha256 != target_hash:
                _cleanup_dir(update_dir)
                logging.error(
                    f"DIVERGÊNCIA CRIPTOGRÁFICA: Esperado {target_hash}, Obtido {computed_sha256}. Arquivo descartado."
                )
                return {
                    "success": False,
                    "error": (
                        f"Falha de integridade criptográfica! O hash SHA-256 do arquivo baixado "
                        f"({computed_sha256[:10]}...) não confere com o publicado ({target_hash[:10]}...). "
                        f"O arquivo corrompido foi descartado imediatamente."
                    ),
                    "code": "SHA256_MISMATCH",
                }

            # Locate target executable
            new_exe_path = None
            if filename.lower().endswith(".exe"):
                new_exe_path = download_dest
            elif filename.lower().endswith(".zip"):
                has_traversal = False
                with zipfile.ZipFile(download_dest, "r") as z:
                    dest_abs = os.path.abspath(update_dir)
                    for member in z.infolist():
                        target_path = os.path.abspath(os.path.join(dest_abs, member.filename))
                        if not target_path.startswith(dest_abs + os.sep) and target_path != dest_abs:
                            has_traversal = True
                            break
                    if not has_traversal:
                        z.extractall(update_dir)

                if has_traversal:
                    _cleanup_dir(update_dir)
                    return {
                        "success": False,
                        "error": "Pacote ZIP inválido ou inseguro (tentativa de path traversal detectada).",
                    }

                for root, _, files in os.walk(update_dir):
                    for file in files:
                        if file.lower() == "fulgorpcista.exe":
                            new_exe_path = os.path.join(root, file)
                            break
                    if new_exe_path:
                        break

            if not new_exe_path or not os.path.exists(new_exe_path):
                _cleanup_dir(update_dir)
                return {"success": False, "error": "Executável FulgorPCista.exe não encontrado no pacote baixado."}

            current_exe = sys.executable if getattr(sys, "frozen", False) else sys.argv[0]
            current_pid = os.getpid()

            # Create updater batch script in temp dir
            bat_path = os.path.join(update_dir, "apply_update.bat")
            with open(bat_path, "w", encoding="utf-8") as bat:
                bat.write(f"""@echo off
chcp 65001 >nul
title Atualizando Fulgor PCista...
echo Aguardando fechamento da versao anterior...
taskkill /F /PID {current_pid} >nul 2>&1
timeout /t 1 /nobreak >nul

echo Substituindo executavel principal...
set RETRIES=0
:retry_copy
copy /Y "{new_exe_path}" "{current_exe}" >nul 2>&1
if not errorlevel 1 goto copy_success
set /a RETRIES+=1
if %RETRIES% leq 10 (
    timeout /t 1 /nobreak >nul
    goto retry_copy
)
echo Erro: Nao foi possivel substituir o executavel.
pause
exit /b 1

:copy_success
if defined LOCALAPPDATA (
    if exist "%LOCALAPPDATA%\\Programs\\FulgorPCista\\FulgorPCista.exe" (
        copy /Y "{new_exe_path}" "%LOCALAPPDATA%\\Programs\\FulgorPCista\\FulgorPCista.exe" >nul 2>&1
    )
)

echo Reiniciando Fulgor PCista...
start "" "{current_exe}"
del "%~f0" & exit
""")

            # Launch batch updater independently
            subprocess.Popen(
                ["cmd.exe", "/c", bat_path],
                creationflags=subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS if sys.platform == "win32" else 0,
            )

            # Schedule clean exit
            threading.Timer(0.5, lambda: os._exit(0)).start()
            return {"success": True, "message": "Atualização verificada com sucesso via SHA-256. Reiniciando aplicativo..."}

        except Exception as e:
            _cleanup_dir(update_dir)
            logging.error(f"Falha durante a aplicação da atualização: {e}", exc_info=True)
            return {"success": False, "error": f"Erro durante atualização: {e}"}
