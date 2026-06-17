"""Libvirt-based snapshot driver — fan out N clones via virsh save/restore.

Save-file layout (LibvirtQemudSave v2):

    [ 0:16] magic "LibvirtQemudSave"
    [16:20] version (uint32 LE)             ← must be 2
    [20:24] data_len  (XML+cookie region size)
    [24:28] was_running flag
    [28:32] compressed flag                 ← we only support 0
    [32:36] cookie_offset (within data_len)
    [36:92] reserved/padding
    [92    : 92+data_len]   data region:  XML \\0 cookie \\0
    [92+data_len :  EOF ]   qemu migration stream
"""

from __future__ import annotations

import dataclasses as dc
import logging
import os
import re
import shutil
import socket
import subprocess
import time
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional


_CLONE_NAME_RE = re.compile(r"agentS-r\d+-c(?P<i>\d+)$")

logger = logging.getLogger(__name__)

_SAVE_HEADER_BYTES = 92
_SAVE_MAGIC = b"LibvirtQemudSave"
_SAVE_VERSION_SUPPORTED = 2
DEFAULT_SSH_PORT_BASE = 9100


@dc.dataclass
class _SaveHeader:
    raw: bytes
    data_len: int
    was_running: int
    compressed: int
    cookie_offset: int


def _read_save_header(path: Path) -> _SaveHeader:
    with path.open("rb") as f:
        raw = f.read(_SAVE_HEADER_BYTES)
    if raw[:16] != _SAVE_MAGIC:
        raise ValueError(f"not a libvirt save image: {raw[:16]!r}")
    version = int.from_bytes(raw[16:20], "little")
    if version != _SAVE_VERSION_SUPPORTED:
        raise ValueError(f"unsupported save version {version}")
    compressed = int.from_bytes(raw[28:32], "little")
    if compressed != 0:
        raise ValueError("compressed save images are not supported")
    return _SaveHeader(
        raw=raw,
        data_len=int.from_bytes(raw[20:24], "little"),
        was_running=int.from_bytes(raw[24:28], "little"),
        compressed=compressed,
        cookie_offset=int.from_bytes(raw[32:36], "little"),
    )


def _split_data_region(region: bytes) -> tuple[bytes, bytes]:
    nul1 = region.find(b"\x00")
    if nul1 < 0:
        raise ValueError("missing NUL after domain XML in save file")
    rest = region[nul1 + 1:]
    nul2 = rest.find(b"\x00")
    cookie = rest[:nul2] if nul2 >= 0 else rest
    return region[:nul1], cookie


def _gen_locally_administered_mac() -> str:
    suffix = os.urandom(3)
    return f"52:54:00:{suffix[0]:02x}:{suffix[1]:02x}:{suffix[2]:02x}"


def _mutate_domain_xml(
    xml_bytes: bytes,
    *,
    new_name: str,
    new_uuid: str,
    new_disk_path: str,
    new_mac: str,
    ssh_host_port: int,
) -> bytes:
    tree = ET.ElementTree(ET.fromstring(xml_bytes))
    root = tree.getroot()

    name_el = root.find("name")
    if name_el is None:
        name_el = ET.SubElement(root, "name")
    name_el.text = new_name
    uuid_el = root.find("uuid")
    if uuid_el is None:
        uuid_el = ET.SubElement(root, "uuid")
    uuid_el.text = new_uuid

    for disk in root.findall(".//disk[@device='disk']"):
        src = disk.find("source")
        if src is not None:
            src.set("file", new_disk_path)
            src.attrib.pop("index", None)

        for bs in list(disk.findall("backingStore")):
            disk.remove(bs)

    devices = root.find("devices")
    if devices is None:
        raise ValueError("domain XML is missing <devices>")
    for iface in list(devices.findall("interface")):
        devices.remove(iface)
    iface = ET.SubElement(devices, "interface", {"type": "user"})
    ET.SubElement(iface, "mac", {"address": new_mac})
    ET.SubElement(iface, "model", {"type": "virtio"})
    pfwd = ET.SubElement(iface, "portForward", {"proto": "tcp"})
    ET.SubElement(pfwd, "range", {"start": str(ssh_host_port), "to": "22"})

    return ET.tostring(root, encoding="utf-8")


class KvmVirshDriver:
    def __init__(
        self,
        *,
        work_dir: Path,
        source_xml: Optional[Path] = None,
        source_domain: str = "agent-s-source",
        base_disk: Optional[Path] = None,
        libvirt_uri: str = "qemu:///system",
        ssh_port_base: int = DEFAULT_SSH_PORT_BASE,
        ready_timeout_s: int = 240,
    ) -> None:
        self.work_dir = Path(work_dir)
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.source_xml = source_xml
        self.source_domain = source_domain
        self.base_disk = base_disk
        self.libvirt_uri = libvirt_uri
        self.ssh_port_base = ssh_port_base
        self.ready_timeout_s = ready_timeout_s

    def launch_source(self, *, round_idx: int) -> str:
        if self.source_xml is not None and not self._domain_defined(self.source_domain):
            self._virsh(["define", str(self.source_xml)], why="register source domain")

        if not self._domain_running(self.source_domain):
            self._virsh(["start", self.source_domain], why="boot source domain")

        if not self._wait_ssh_via_libvirt(self.source_domain, port=22):
            raise TimeoutError(f"source {self.source_domain} sshd not reachable")
        return self.source_domain

    def clone(self, *, src: str, n: int, round_idx: int) -> list[str]:
        save_path = self.work_dir / f"r{round_idx}-{src}.save"

        self._virsh(["save", src, str(save_path)], why="checkpoint source")
        clones: list[str] = []
        try:
            for i in range(n):
                clones.append(self._materialise_clone(
                    save_template=save_path,
                    branch_idx=i,
                    round_idx=round_idx,
                ))
        finally:
            self._virsh(["restore", str(save_path)], why="resume source")
            try:
                save_path.unlink()
            except FileNotFoundError:
                pass

        return clones

    def screenshot(self, target: str) -> Optional[bytes]:
        port = self._target_ssh_port(target)
        if port is None:
            return None
        from . import SCREENSHOT_PY
        try:
            proc = subprocess.run([
                "ssh", "-p", str(port),
                "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes",
                "-o", "ConnectTimeout=4",
                "user@127.0.0.1",
                "DISPLAY=:0 XAUTHORITY=/home/user/.Xauthority python3",
            ], input=SCREENSHOT_PY.encode(), capture_output=True, timeout=15)
            return proc.stdout if proc.returncode == 0 and proc.stdout else None
        except Exception as e:
            logger.warning("ssh screenshot from %s failed: %s", target, e)
            return None

    def exec(self, target: str, cmd: str, *, timeout: int = 30
             ) -> subprocess.CompletedProcess:
        port = self._target_ssh_port(target)
        if port is None:
            raise RuntimeError(f"unknown target {target!r}")
        return subprocess.run([
            "ssh", "-p", str(port),
            "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes",
            "user@127.0.0.1", "bash", "-lc", cmd,
        ], capture_output=True, text=True, timeout=timeout)

    def working_set_bytes(self, target: str) -> Optional[int]:
        """qemu's RSS via libvirt's domid → /proc/<pid>/status. One
        ``virsh domid`` + one file read; sub-ms."""
        try:
            r = self._virsh(["domid", target], why=f"domid {target}",
                             check=False)
        except Exception:
            return None
        if r.returncode != 0:
            return None
        try:
            domid = int(r.stdout.strip())
            pid_text = Path(f"/var/run/libvirt/qemu/{target}.pid").read_text()
            pid = int(pid_text.strip())
            for line in Path(f"/proc/{pid}/status").read_text().splitlines():
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) * 1024
        except (OSError, ValueError):
            return None
        return None

    def _target_ssh_port(self, target: str) -> Optional[int]:

        m = _CLONE_NAME_RE.match(target)
        if not m:
            return None
        return self.ssh_port_base + int(m.group("i"))

    def teardown(self, *, src: Optional[str], clones: list[str],
                 round_idx: int) -> None:
        targets = list(clones)
        if src:
            targets.append(src)
        for name in targets:
            self._virsh(["destroy", name], why=f"force-stop {name}", check=False)
            self._virsh(["undefine", name], why=f"undefine {name}", check=False)

        for f in self.work_dir.glob(f"r{round_idx}-*"):
            try:
                f.unlink()
            except OSError as e:
                logger.warning("could not delete %s: %s", f, e)

    def _materialise_clone(
        self,
        *,
        save_template: Path,
        branch_idx: int,
        round_idx: int,
    ) -> str:
        if self.base_disk is None:
            raise RuntimeError("KvmVirshDriver.base_disk is required for clone()")

        clone_name = f"agentS-r{round_idx}-c{branch_idx}"
        new_uuid = str(uuid.uuid4())
        new_mac = _gen_locally_administered_mac()
        ssh_port = self.ssh_port_base + branch_idx

        clone_disk = self.work_dir / f"r{round_idx}-{clone_name}.qcow2"
        clone_save = self.work_dir / f"r{round_idx}-{clone_name}.save"

        subprocess.run(
            ["qemu-img", "create", "-f", "qcow2",
             "-b", str(self.base_disk), "-F", "qcow2", str(clone_disk)],
            check=True, capture_output=True,
        )
        shutil.copyfile(save_template, clone_save)
        self._patch_save_file(
            clone_save,
            new_name=clone_name, new_uuid=new_uuid,
            new_disk_path=str(clone_disk), new_mac=new_mac,
            ssh_host_port=ssh_port,
        )
        self._virsh(["restore", str(clone_save)], why=f"start {clone_name}")

        if not self._wait_ssh_on_localhost(ssh_port):
            raise TimeoutError(f"clone {clone_name} sshd on :{ssh_port} not reachable")
        return clone_name

    def _patch_save_file(
        self,
        path: Path,
        *,
        new_name: str,
        new_uuid: str,
        new_disk_path: str,
        new_mac: str,
        ssh_host_port: int,
    ) -> None:
        hdr = _read_save_header(path)

        with path.open("rb") as f:
            f.seek(_SAVE_HEADER_BYTES)
            data_region = f.read(hdr.data_len)
        old_xml, cookie = _split_data_region(data_region)

        new_xml = _mutate_domain_xml(
            old_xml,
            new_name=new_name, new_uuid=new_uuid,
            new_disk_path=new_disk_path, new_mac=new_mac,
            ssh_host_port=ssh_host_port,
        )

        payload = new_xml + b"\x00" + cookie + b"\x00"
        if len(payload) > hdr.data_len:
            raise RuntimeError(
                f"patched XML grew past data_len: {len(payload)} > {hdr.data_len}"
            )
        new_region = payload + b"\x00" * (hdr.data_len - len(payload))
        new_cookie_offset = len(new_xml) + 1
        new_header = bytearray(hdr.raw)
        new_header[32:36] = new_cookie_offset.to_bytes(4, "little")

        with path.open("r+b") as f:
            f.seek(0)
            f.write(bytes(new_header))
            f.seek(_SAVE_HEADER_BYTES)
            f.write(new_region)

    def _virsh(self, args: list[str], *, why: str, check: bool = True
               ) -> subprocess.CompletedProcess:
        cmd = ["virsh", "-c", self.libvirt_uri, *args]
        logger.debug("virsh: %s  # %s", " ".join(cmd), why)
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if check and proc.returncode != 0:
            raise RuntimeError(
                f"virsh {' '.join(args)} (purpose: {why}) failed "
                f"rc={proc.returncode}: {proc.stderr.strip()}"
            )
        return proc

    def _domain_defined(self, name: str) -> bool:
        proc = self._virsh(["list", "--all", "--name"], why="list domains", check=False)
        return name in (proc.stdout or "").split()

    def _domain_running(self, name: str) -> bool:
        proc = self._virsh(["domstate", name], why="check domain state", check=False)
        return (proc.stdout or "").strip() == "running"

    def _wait_ssh_on_localhost(self, port: int) -> bool:
        deadline = time.monotonic() + self.ready_timeout_s
        while time.monotonic() < deadline:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.0)
                try:
                    s.connect(("127.0.0.1", port))
                    if s.recv(7).startswith(b"SSH-"):
                        return True
                except (socket.timeout, ConnectionRefusedError, OSError):
                    pass
            time.sleep(0.25)
        return False

    def _wait_ssh_via_libvirt(self, name: str, *, port: int) -> bool:
        deadline = time.monotonic() + self.ready_timeout_s
        while time.monotonic() < deadline:
            r = self._virsh(["domifaddr", name], why="resolve guest IP", check=False)
            ip = self._parse_first_ip(r.stdout or "")
            if ip:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1.0)
                    try:
                        s.connect((ip, port))
                        if s.recv(7).startswith(b"SSH-"):
                            return True
                    except (socket.timeout, ConnectionRefusedError, OSError):
                        pass
            time.sleep(0.25)
        return False

    @staticmethod
    def _parse_first_ip(domifaddr_out: str) -> Optional[str]:
        for line in domifaddr_out.splitlines():
            for tok in line.split():
                if "/" in tok and tok.split("/")[0].count(".") == 3:
                    return tok.split("/")[0]
        return None
