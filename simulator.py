import random
import threading
import time
import uuid
from typing import Dict, List

from database import Database
from radius_client import (
    ACCESS_ACCEPT, ACCT_INTERIM, ACCT_START, ACCT_STOP,
    build_access_request, build_accounting_request,
    parse_response, send_packet,
)


class CPESession(threading.Thread):
    """Simulates a single CPE RADIUS lifecycle."""

    def __init__(self, cpe_id: int, cfg: dict, db: Database):
        super().__init__(daemon=True, name=f"CPE-{cpe_id}")
        self.cpe_id   = cpe_id
        self.cfg      = cfg
        self.db       = db
        self._stop_event = threading.Event()   # ← renomeado de _stop
        self._ident   = random.randint(1, 254)
        self.session_id = uuid.uuid4().hex[:8].upper()

    # ── helpers ───────────────────────────────────────────────────────────────

    def stop(self):
        self._stop_event.set()   # ← atualizado

    def _nid(self) -> int:
        self._ident = (self._ident % 255) + 1
        return self._ident

    def _log(self, level: str, msg: str, ptype: str = None):
        try:
            self.db.add_log(
                self.cfg["sim_id"], self.cpe_id, level,
                f"[{self.cfg['username']}@{self.cfg['proxy_ip']}] {msg}",
                ptype,
            )
        except Exception:
            pass

    @staticmethod
    def _mac() -> str:
        return ":".join(f"{random.randint(0, 255):02X}" for _ in range(6))

    def _send(self, pkt: bytes, port: int) -> dict | None:
        try:
            raw = send_packet(
                pkt, self.cfg["server_ip"], port,
                self.cfg["proxy_ip"], self.cfg["proxy_port"],
                timeout=60,
            )
            return parse_response(raw) if raw else None
        except Exception as e:
            raise ConnectionError(str(e)) from e

    # ── main lifecycle ────────────────────────────────────────────────────────

    def run(self):
        try:
            self._lifecycle()
        except Exception as e:
            self._log("ERROR", f"Unhandled exception: {e}")
            self.db.cpe_status(self.cpe_id, "failed")

    def _lifecycle(self):
        cfg     = self.cfg
        nas_port = random.randint(1000, 60000)
        mac     = self._mac()

        # ── 1. Access-Request ─────────────────────────────────────────────────
        self._log("INFO", "Sending Access-Request", "Access-Request")
        self.db.cpe_status(self.cpe_id, "authenticating")

        try:
            pkt = build_access_request(
                identifier=self._nid(),
                secret=cfg["secret"],
                username=cfg["username"],
                password=cfg["password"],
                nas_ip=cfg["proxy_ip"],
                nas_port=nas_port,
                calling_station=mac,
                nas_identifier=f"CPE-{cfg['proxy_ip']}",
            )
            resp = self._send(pkt, cfg["auth_port"])
        except Exception as e:
            self._log("ERROR", f"Access-Request error: {e}", "Access-Request")
            self.db.cpe_status(self.cpe_id, "failed")
            return

        if not resp:
            self._log("ERROR", "No response (timeout)", "Access-Request")
            self.db.cpe_status(self.cpe_id, "failed")
            return

        if resp["code"] != ACCESS_ACCEPT:
            self._log("WARN", f"Rejected: {resp['code_name']}", resp["code_name"])
            self.db.cpe_status(self.cpe_id, "rejected")
            return

        framed_ip = resp.get("framed_ip")
        self._log(
            "INFO",
            f"Access-Accept ✓  Framed-IP: {framed_ip or 'N/A'}",
            "Access-Accept",
        )
        self.db.cpe_session(self.cpe_id, self.session_id, framed_ip)

        if self._stop_event.is_set():   # ← atualizado
            return

        # ── 2. Accounting-Start ───────────────────────────────────────────────
        try:
            pkt = build_accounting_request(
                identifier=self._nid(), secret=cfg["secret"],
                username=cfg["username"], session_id=self.session_id,
                status_type=ACCT_START, nas_ip=cfg["proxy_ip"],
                nas_port=nas_port, framed_ip=framed_ip,
                calling_station=mac,
                nas_identifier=f"CPE-{cfg['proxy_ip']}",
            )
            resp = self._send(pkt, cfg["acct_port"])
            code_name = resp["code_name"] if resp else "No response"
            self._log("INFO", f"Accounting-Start → {code_name}", "Accounting-Start")
        except Exception as e:
            self._log("ERROR", f"Accounting-Start error: {e}", "Accounting-Start")

        self.db.cpe_status(self.cpe_id, "active")
        self.db.cpe_started(self.cpe_id)

        # ── 3. Interim-Updates ────────────────────────────────────────────────
        t0 = time.time()
        in_oct = out_oct = in_pkts = out_pkts = 0

        last_interim = t0

        while not self._stop_event.is_set():
            now = time.time()
            elapsed = int(now - t0)

            if cfg.get("term_time") and elapsed >= cfg["term_time"]:
                break

            if now - last_interim >= cfg["interim_interval"]:
                last_interim = now
                in_oct   += random.randint(500_000,  10_000_000)
                out_oct  += random.randint(100_000,   2_000_000)
                in_pkts  += random.randint(  5_000,    100_000)
                out_pkts += random.randint(  1_000,     20_000)

                try:
                    pkt = build_accounting_request(
                        identifier=self._nid(), secret=cfg["secret"],
                        username=cfg["username"], session_id=self.session_id,
                        status_type=ACCT_INTERIM, nas_ip=cfg["proxy_ip"],
                        nas_port=nas_port, session_time=elapsed,
                        in_octets=in_oct, out_octets=out_oct,
                        in_pkts=in_pkts, out_pkts=out_pkts,
                        framed_ip=framed_ip, calling_station=mac,
                        nas_identifier=f"CPE-{cfg['proxy_ip']}",
                    )
                    resp = self._send(pkt, cfg["acct_port"])
                    code_name = resp["code_name"] if resp else "No response"
                    self._log(
                        "INFO",
                        f"Interim-Update | t={elapsed}s | "
                        f"↓{in_oct // 1_048_576}MB ↑{out_oct // 1_048_576}MB"
                        f" | {code_name}",
                        "Accounting-Interim",
                    )
                    self.db.cpe_updated(self.cpe_id, download_bytes=in_oct, upload_bytes=out_oct)
                except Exception as e:
                    self._log("WARN", f"Interim-Update error: {e}", "Accounting-Interim")

            if self._stop_event.wait(1.0):
                break

        # ── 4. Accounting-Stop ────────────────────────────────────────────────
        elapsed = int(time.time() - t0)
        try:
            pkt = build_accounting_request(
                identifier=self._nid(), secret=cfg["secret"],
                username=cfg["username"], session_id=self.session_id,
                status_type=ACCT_STOP, nas_ip=cfg["proxy_ip"],
                nas_port=nas_port, session_time=elapsed,
                in_octets=in_oct, out_octets=out_oct,
                in_pkts=in_pkts, out_pkts=out_pkts,
                framed_ip=framed_ip, calling_station=mac,
                nas_identifier=f"CPE-{cfg['proxy_ip']}",
            )
            resp = self._send(pkt, cfg["acct_port"])
            code_name = resp["code_name"] if resp else "No response"
            self._log(
                "INFO",
                f"Accounting-Stop | t={elapsed}s | "
                f"↓{in_oct // 1_048_576}MB ↑{out_oct // 1_048_576}MB"
                f" | {code_name}",
                "Accounting-Stop",
            )
        except Exception as e:
            self._log("ERROR", f"Accounting-Stop error: {e}", "Accounting-Stop")

        self.db.cpe_status(self.cpe_id, "finished")
        self.db.cpe_ended(self.cpe_id, download_bytes=in_oct, upload_bytes=out_oct)
        self._log("INFO", f"Session finished. Duration: {elapsed}s", "Session-End")


# ── Simulation Manager ────────────────────────────────────────────────────────

class SimulationManager:
    def __init__(self, db: Database):
        self.db = db
        self._threads: Dict[int, List[CPESession]] = {}
        self._lock = threading.Lock()

    def start(self, sim_id: int):
        sim  = self.db.get_simulation(sim_id)
        srv  = self.db.get_server(sim["radius_server_id"])
        cpes = self.db.get_cpes(sim_id)

        sessions = []
        for cpe in cpes:
            self.db.cpe_status(cpe["id"], "pending")
            cfg = {
                "sim_id":           sim_id,
                "server_ip":        srv["ip"],
                "auth_port":        srv["auth_port"],
                "acct_port":        srv["acct_port"],
                "secret":           sim["secret"],
                "proxy_ip":         cpe["proxy_ip"],
                "proxy_port":       cpe["proxy_port"],
                "username":         cpe["username"],
                "password":         cpe["password"],
                "interim_interval": sim["interim_update_interval"],
                "term_time":        sim["termination_time"],
            }
            sessions.append(CPESession(cpe["id"], cfg, self.db))

        with self._lock:
            self._threads[sim_id] = sessions

        self.db.set_sim_status(sim_id, "running")
        
        def _launcher():
            for t in sessions:
                sim_curr = self.db.get_simulation(sim_id)
                if not sim_curr or sim_curr["status"] == "stopped":
                    break
                t.start()
                time.sleep(1.0)

        threading.Thread(target=_launcher, daemon=True).start()

    def stop(self, sim_id: int):
        with self._lock:
            sessions = self._threads.get(sim_id, [])
        
        def _stopper():
            for t in sessions:
                t.stop()
                time.sleep(1.0)
            self.db.set_sim_status(sim_id, "stopped")

        threading.Thread(target=_stopper, daemon=True).start()

    def is_running(self, sim_id: int) -> bool:
        with self._lock:
            sessions = self._threads.get(sim_id, [])
        return any(t.is_alive() for t in sessions)

    def active_count(self, sim_id: int) -> int:
        with self._lock:
            sessions = self._threads.get(sim_id, [])
        return sum(1 for t in sessions if t.is_alive())