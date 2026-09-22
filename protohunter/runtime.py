"""Cooperative cancellation and bounded binary string iteration."""
import os
import re
import signal
import subprocess


class AnalysisCancelled(Exception):
    pass


def binary_strings(data, utf16=False, check=None, window=1024**2):
    pattern = re.compile(rb'(?:[\x20-\x7e]\x00){3,16384}' if utf16 else rb'[\x20-\x7e]{3,16384}')
    overlap = 32768 if utf16 else 16384
    position = 0
    while position < len(data):
        if check:
            check()
        edge = min(len(data), position + window)
        next_position = edge
        for index, match in enumerate(pattern.finditer(data, position, min(len(data), edge + overlap))):
            if match.start() >= edge:
                break
            if check and index % 512 == 0:
                check()
            yield match.start(), match.group()
            if match.end() >= edge:
                next_position = match.end()
                break
        position = next_position


def stop_decoder(process):
    if process.poll() is not None:
        return
    if os.name == 'nt':
        try:
            subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False)
        except (OSError, subprocess.TimeoutExpired):
            if process.poll() is None:
                process.kill()
    else:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        if os.name != 'nt':
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            process.kill()
        process.wait(timeout=3)
