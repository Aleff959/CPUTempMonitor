import os
import sys
import json
import re
import urllib.request
import tempfile
import zipfile
import subprocess
import threading
import logging

GITHUB_REPO = "Aleff959/CPUTempMonitor"
API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"


def _parse_version_tuple(v_str):
    """Parse version string into tuple of ints for comparison."""
    m = re.findall(r"\d+", str(v_str))
    return tuple(int(x) for x in m) if m else (0,)


def _parse_comp_number(text):
    """Extract compilation number from text (e.g. 'Comp. 19' -> 19)."""
    m = re.search(r"comp\.?\s*(\d+)", str(text), re.IGNORECASE)
    return int(m.group(1)) if m else 0


class AppUpdater:
    def __init__(self, current_version="1.3.0", current_comp=20):
        self.current_version = current_version
        self.current_comp = current_comp
        self.update_info = None

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
            with urllib.request.urlopen(req, timeout=6.0) as resp:
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

            self.update_info = {
                "success": True,
                "has_update": has_update,
                "current_version": f"v{self.current_version} | Comp. {self.current_comp}",
                "latest_version": tag_name,
                "latest_title": release_name,
                "changelog": body,
                "download_url": download_url,
                "asset_name": asset_name,
                "asset_size_mb": round(asset_size / (1024 * 1024), 1) if asset_size else 0.0,
            }
            return self.update_info

        except Exception as e:
            logging.error(f"Error checking for updates: {e}", exc_info=True)
            return {
                "success": False,
                "has_update": False,
                "error": str(e),
                "current_version": f"v{self.current_version} | Comp. {self.current_comp}",
            }

    def apply_update(self, download_url=None):
        """Download new version, generate standalone bat updater and restart cleanly."""
        url = download_url or (self.update_info.get("download_url") if self.update_info else None)
        if not url:
            return {"success": False, "error": "URL de download não encontrada."}

        try:
            update_dir = os.path.join(tempfile.gettempdir(), "FulgorPCista_Update")
            os.makedirs(update_dir, exist_ok=True)

            filename = url.split("/")[-1].split("?")[0]
            download_dest = os.path.join(update_dir, filename)

            logging.info(f"Downloading update from {url} to {download_dest}...")
            req = urllib.request.Request(url, headers={"User-Agent": "FulgorPCista-Updater"})
            with urllib.request.urlopen(req, timeout=30.0) as resp, open(download_dest, "wb") as f:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)

            # Determine where the new FulgorPCista.exe is located
            new_exe_path = None
            if filename.lower().endswith(".exe"):
                new_exe_path = download_dest
            elif filename.lower().endswith(".zip"):
                with zipfile.ZipFile(download_dest, "r") as z:
                    z.extractall(update_dir)
                for root, _, files in os.walk(update_dir):
                    for file in files:
                        if file.lower() == "fulgorpcista.exe":
                            new_exe_path = os.path.join(root, file)
                            break
                    if new_exe_path:
                        break

            if not new_exe_path or not os.path.exists(new_exe_path):
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
timeout /t 1 /nobreak >nul
taskkill /F /PID {current_pid} >nul 2>&1
timeout /t 1 /nobreak >nul

echo Substituindo executavel principal...
copy /Y "{new_exe_path}" "{current_exe}" >nul

if exist "C:\\Users\\Alpha\\AppData\\Local\\Programs\\FulgorPCista\\FulgorPCista.exe" (
    copy /Y "{new_exe_path}" "C:\\Users\\Alpha\\AppData\\Local\\Programs\\FulgorPCista\\FulgorPCista.exe" >nul
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
            return {"success": True, "message": "Atualização baixada. Reiniciando aplicativo..."}

        except Exception as e:
            logging.error(f"Failed to apply update: {e}", exc_info=True)
            return {"success": False, "error": str(e)}
