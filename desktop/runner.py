import os
import subprocess
import sys
import tempfile
import threading
from pathlib import Path


class Runner:
    def __init__(self, name):
        self.name = name
        self.process = None
        self.marker = None
        self.lock = threading.Lock()
        self.last_stdout = ""

    def binary(self):
        if getattr(sys, "frozen", False):
            path = Path(sys._MEIPASS) / (self.name + "-cli.exe")
        else:
            root = Path(__file__).resolve().parents[1]
            path = root / "bin" / (self.name + "-cli" + (".exe" if os.name == "nt" else ""))
        if not path.is_file():
            raise ValueError(
                "No se encontró el motor. Compila el CLI o utiliza el ejecutable portable."
            )
        return path

    def run(self, args, note):
        with tempfile.TemporaryDirectory(prefix=self.name + "-") as temporary:
            self.marker = Path(temporary) / "cancel"
            command = [
                str(self.binary()),
                *map(str, args),
                "--cancel-file",
                str(self.marker),
            ]
            flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=flags,
            )
            with self.lock:
                self.process = process
            lines = []
            for line in process.stderr:
                text = line.decode("utf-8", errors="replace").strip()
                if text:
                    lines.append(text)
                    note(text)
            stdout = process.stdout.read()
            process.wait()
            self.last_stdout = stdout.decode("utf-8", errors="replace")
            stderr = "\n".join(lines).encode()
            with self.lock:
                self.process = None
                self.marker = None
            messages = stderr.decode("utf-8", errors="replace").splitlines()
            if messages:
                note(messages[-1])
            if process.returncode:
                if any("cancel" in line.lower() for line in messages):
                    return False
                raise ValueError("\n".join(messages[-5:]) or "El motor terminó con un error.")
            return True

    def cancel(self):
        with self.lock:
            if self.marker:
                try:
                    self.marker.touch()
                except OSError:
                    pass
