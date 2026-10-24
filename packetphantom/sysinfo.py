"""Ressources de la machine pour le monitoring : processeur, mémoire, carte graphique.

Sans dépendance : /proc sous Linux, os.times() partout. Le GPU est lu avec
`nvidia-smi` (NVIDIA, arguments fixes, sans shell, délai borné) ou dans sysfs :
taux d'utilisation pour AMD, fréquence seulement pour Intel (i915 n'expose pas
l'utilisation sans droits root). Ce qui n'est pas mesurable vaut None : l'interface
le dit plutôt que d'afficher un faux zéro.
"""
from __future__ import annotations

import glob
import os
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path

GPU_TTL = 3.0       # s : nvidia-smi coûte quelques dizaines de ms, on ne l'appelle pas à chaque requête
GPU_TIMEOUT = 2.0   # s
VENDORS = {"0x8086": "Intel", "0x10de": "NVIDIA", "0x1002": "AMD"}
NVIDIA_QUERY = ["--query-gpu=name,utilization.gpu,memory.used,memory.total", "--format=csv,noheader,nounits"]


# ------------------------------------------------------------------ lecture (fonctions pures, testables)

def parse_proc_stat(text: str) -> tuple[int, int] | None:
    """Première ligne de /proc/stat → (temps inactif, temps total) en jiffies."""
    fields = text.split("\n", 1)[0].split()
    if len(fields) < 5 or fields[0] != "cpu":
        return None
    values = [int(v) for v in fields[1:9]]
    idle = values[3] + (values[4] if len(values) > 4 else 0)   # idle + iowait
    return idle, sum(values)


def parse_meminfo(text: str) -> tuple[int, int] | None:
    """/proc/meminfo → (octets utilisés, octets au total) ; « utilisée » = total - disponible."""
    values = {}
    for line in text.splitlines():
        key, _, rest = line.partition(":")
        parts = rest.split()
        if parts:
            values[key] = int(parts[0]) * 1024
    if "MemTotal" not in values or "MemAvailable" not in values:
        return None
    return values["MemTotal"] - values["MemAvailable"], values["MemTotal"]


def parse_nvidia(output: str) -> dict | None:
    """Première ligne de nvidia-smi (csv, sans unités) → description du GPU."""
    parts = [p.strip() for p in output.strip().split("\n", 1)[0].split(",")]
    if len(parts) != 4:
        return None
    try:
        util, used, total = float(parts[1]), float(parts[2]), float(parts[3])
    except ValueError:
        return None
    mib = 1024 * 1024
    return {"vendor": "NVIDIA", "name": parts[0], "util": util, "vram_used": int(used * mib), "vram_total": int(total * mib)}


def _read(path: str) -> str | None:
    try:
        return Path(path).read_text(encoding="ascii", errors="replace")
    except OSError:
        return None


# ------------------------------------------------------------------ mesures

class SystemProbe:
    """Mesures avec état : l'usage CPU est un écart entre deux appels successifs."""

    def __init__(self):
        self._lock = threading.Lock()
        self._cpu_sample: tuple[int, int] | None = None
        self._proc_sample: tuple[float, float] | None = None
        self._gpu: tuple[float, dict | None] = (0.0, None)

    def cpu(self) -> dict:
        cores = os.cpu_count() or 1
        now = time.monotonic()
        times = os.times()
        busy = times.user + times.system
        stat = _read("/proc/stat")
        sample = parse_proc_stat(stat) if stat else None
        with self._lock:
            system = None
            if sample and self._cpu_sample:
                d_idle, d_total = sample[0] - self._cpu_sample[0], sample[1] - self._cpu_sample[1]
                system = round(100 * (1 - d_idle / d_total), 1) if d_total > 0 else None
            process = None
            if self._proc_sample and now > self._proc_sample[0]:
                process = round(100 * (busy - self._proc_sample[1]) / (now - self._proc_sample[0]) / cores, 1)
            self._cpu_sample = sample or self._cpu_sample
            self._proc_sample = (now, busy)
        try:
            load = [round(v, 2) for v in os.getloadavg()]
        except (AttributeError, OSError):   # Windows
            load = None
        return {"system": system, "process": process, "cores": cores, "load": load}

    @staticmethod
    def memory(process_rss: int | None) -> dict:
        meminfo = _read("/proc/meminfo")
        parsed = parse_meminfo(meminfo) if meminfo else None
        used, total = parsed if parsed else (None, None)
        return {"used": used, "total": total, "process": process_rss}

    def gpu(self) -> dict | None:
        with self._lock:
            stamp, cached = self._gpu
            if time.monotonic() - stamp < GPU_TTL:
                return cached
        info = self._probe_gpu()
        with self._lock:
            self._gpu = (time.monotonic(), info)
        return info

    @staticmethod
    def _probe_gpu() -> dict | None:
        binary = shutil.which("nvidia-smi")
        if binary:
            try:
                done = subprocess.run([binary, *NVIDIA_QUERY], capture_output=True, text=True,
                                      timeout=GPU_TIMEOUT, check=False)
            except (OSError, subprocess.SubprocessError):
                done = None
            if done is not None and done.returncode == 0 and (info := parse_nvidia(done.stdout)):
                return info
        for busy_path in sorted(glob.glob("/sys/class/drm/card*/device/gpu_busy_percent")):   # AMD (amdgpu)
            device = os.path.dirname(busy_path)
            busy, used, total = (_read(busy_path), _read(f"{device}/mem_info_vram_used"),
                                 _read(f"{device}/mem_info_vram_total"))
            try:
                return {"vendor": "AMD", "name": (_read(f"{device}/product_name") or "GPU AMD").strip() or "GPU AMD",
                        "util": float(busy), "vram_used": int(used) if used else None,
                        "vram_total": int(total) if total else None}
            except (TypeError, ValueError):
                continue
        return SystemProbe._probe_drm()

    @staticmethod
    def _probe_drm() -> dict | None:
        """Autre carte (Intel intégrée…) : constructeur, pilote et fréquence quand ils sont exposés."""
        for card in sorted(glob.glob("/sys/class/drm/card*")):
            if not re.fullmatch(r"card\d+", os.path.basename(card)):   # card0-HDMI-A-1 : une sortie, pas une carte
                continue
            vendor = VENDORS.get((_read(f"{card}/device/vendor") or "").strip())
            if vendor is None:
                continue
            driver = os.path.basename(os.path.realpath(f"{card}/device/driver"))
            freq, freq_max = _read(f"{card}/gt_act_freq_mhz"), _read(f"{card}/gt_max_freq_mhz")
            try:
                freq_mhz, freq_max_mhz = (int(freq), int(freq_max)) if freq and freq_max else (None, None)
            except ValueError:
                freq_mhz = freq_max_mhz = None
            return {"vendor": vendor, "name": f"GPU {vendor} ({driver})", "util": None, "vram_used": None,
                    "vram_total": None, "freq_mhz": freq_mhz, "freq_max_mhz": freq_max_mhz}
        return None


PROBE = SystemProbe()
