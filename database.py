import sqlite3
import threading
from typing import List, Dict, Optional

DB_PATH = "radius_simulator.db"


class Database:
    def __init__(self, path: str = DB_PATH):
        self.path = path
        self._lock = threading.Lock()
        self._init_db()

    def _conn(self):
        c = sqlite3.connect(self.path, check_same_thread=False)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA foreign_keys=ON")
        return c

    def _init_db(self):
        with self._lock:
            conn = self._conn()
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS radius_servers (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    name        TEXT NOT NULL,
                    ip          TEXT NOT NULL,
                    auth_port   INTEGER DEFAULT 1812,
                    acct_port   INTEGER DEFAULT 1813,
                    created_at  TEXT DEFAULT (datetime('now','localtime'))
                );

                CREATE TABLE IF NOT EXISTS proxies (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip           TEXT NOT NULL,
                    port         INTEGER NOT NULL,
                    country      TEXT,
                    country_code TEXT,
                    asn          INTEGER,
                    isp          TEXT,
                    protocol     TEXT DEFAULT 'socks5',
                    speed_ms     REAL,
                    anonymity    TEXT,
                    location     TEXT,
                    loaded_at    TEXT DEFAULT (datetime('now','localtime')),
                    UNIQUE(ip, port)
                );

                CREATE TABLE IF NOT EXISTS simulations (
                    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
                    name                    TEXT NOT NULL,
                    radius_server_id        INTEGER NOT NULL,
                    secret                  TEXT NOT NULL,
                    interim_update_interval INTEGER DEFAULT 300,
                    termination_time        INTEGER,
                    lcp_protocols           TEXT DEFAULT 'PAP',
                    status                  TEXT DEFAULT 'created',
                    created_at              TEXT DEFAULT (datetime('now','localtime')),
                    FOREIGN KEY (radius_server_id) REFERENCES radius_servers(id)
                );

                CREATE TABLE IF NOT EXISTS simulation_cpes (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    simulation_id   INTEGER NOT NULL,
                    proxy_ip        TEXT NOT NULL,
                    proxy_port      INTEGER NOT NULL,
                    username        TEXT NOT NULL,
                    password        TEXT NOT NULL,
                    session_id      TEXT,
                    lcp_protocol    TEXT DEFAULT 'PAP',
                    status          TEXT DEFAULT 'pending',
                    framed_ip       TEXT,
                    started_at      TEXT,
                    last_update_at  TEXT,
                    ended_at        TEXT,
                    download_bytes  INTEGER DEFAULT 0,
                    upload_bytes    INTEGER DEFAULT 0,
                    FOREIGN KEY (simulation_id) REFERENCES simulations(id)
                );

                CREATE TABLE IF NOT EXISTS logs (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    simulation_id INTEGER,
                    cpe_id        INTEGER,
                    timestamp     TEXT DEFAULT (datetime('now','localtime')),
                    level         TEXT DEFAULT 'INFO',
                    packet_type   TEXT,
                    message       TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_logs_sim  ON logs(simulation_id);
                CREATE INDEX IF NOT EXISTS idx_logs_ts   ON logs(id DESC);
                CREATE INDEX IF NOT EXISTS idx_cpes_sim  ON simulation_cpes(simulation_id);
                CREATE INDEX IF NOT EXISTS idx_proxy_cc  ON proxies(country_code);
            """)
            try:
                conn.execute("ALTER TABLE simulation_cpes ADD COLUMN download_bytes INTEGER DEFAULT 0")
            except Exception:
                pass
            try:
                conn.execute("ALTER TABLE simulation_cpes ADD COLUMN upload_bytes INTEGER DEFAULT 0")
            except Exception:
                pass
            try:
                conn.execute("ALTER TABLE simulation_cpes ADD COLUMN lcp_protocol TEXT DEFAULT 'PAP'")
            except Exception:
                pass
            try:
                conn.execute("ALTER TABLE simulations ADD COLUMN lcp_protocols TEXT DEFAULT 'PAP'")
            except Exception:
                pass
            conn.commit()
            conn.close()

    # ── helpers ──────────────────────────────────────────────────────────────

    def _exec(self, sql: str, params=(), *, many=False,
              one=False, all_=False, rowid=False):
        with self._lock:
            conn = self._conn()
            try:
                if many:
                    cur = conn.executemany(sql, params)
                else:
                    cur = conn.execute(sql, params)
                conn.commit()
                if one:
                    row = cur.fetchone()
                    return dict(row) if row else None
                if all_:
                    return [dict(r) for r in cur.fetchall()]
                if rowid:
                    return cur.lastrowid
            finally:
                conn.close()

    # ── RADIUS Servers ────────────────────────────────────────────────────────

    def add_server(self, name, ip, auth_port, acct_port) -> int:
        return self._exec(
            "INSERT INTO radius_servers(name,ip,auth_port,acct_port) VALUES(?,?,?,?)",
            (name, ip, auth_port, acct_port), rowid=True)

    def get_servers(self) -> List[Dict]:
        return self._exec("SELECT * FROM radius_servers ORDER BY id", all_=True)

    def get_server(self, sid: int) -> Optional[Dict]:
        return self._exec("SELECT * FROM radius_servers WHERE id=?", (sid,), one=True)

    def delete_server(self, sid: int):
        self._exec("DELETE FROM radius_servers WHERE id=?", (sid,))

    # ── Proxies ───────────────────────────────────────────────────────────────

    def upsert_proxies(self, proxies: list) -> int:
        rows = [
            (p.get('ip'), p.get('port'),
             p.get('country'), p.get('country_code'),
             p.get('asn'), p.get('isp'), p.get('protocol', 'socks5'),
             float(p.get('speed_ms') or 0),
             p.get('anonymity'), p.get('location'))
            for p in proxies if p.get('ip') and p.get('port')
        ]
        self._exec("""
            INSERT OR REPLACE INTO proxies
            (ip,port,country,country_code,asn,isp,protocol,speed_ms,anonymity,location)
            VALUES(?,?,?,?,?,?,?,?,?,?)
        """, rows, many=True)
        return len(rows)

    def get_proxies(self, country_codes: List[str] = None, limit: int = 50) -> List[Dict]:
        if country_codes:
            ph = ",".join("?" * len(country_codes))
            return self._exec(
                f"SELECT * FROM proxies WHERE country_code IN ({ph}) "
                f"ORDER BY speed_ms ASC LIMIT ?",
                (*country_codes, limit), all_=True)
        return self._exec(
            "SELECT * FROM proxies ORDER BY speed_ms ASC LIMIT ?",
            (limit,), all_=True)

    def proxy_count(self) -> int:
        r = self._exec("SELECT COUNT(*) c FROM proxies", one=True)
        return r['c'] if r else 0

    def proxy_countries(self) -> List[str]:
        rows = self._exec(
            "SELECT DISTINCT country_code FROM proxies "
            "WHERE country_code IS NOT NULL ORDER BY country_code", all_=True)
        return [r['country_code'] for r in (rows or [])]

    def proxy_by_country(self) -> List[Dict]:
        return self._exec("""
            SELECT COALESCE(country,'Unknown') AS country,
                   COALESCE(country_code,'XX') AS code,
                   COUNT(*) AS qty
            FROM proxies
            GROUP BY country_code
            ORDER BY qty DESC
        """, all_=True)

    def clear_proxies(self):
        self._exec("DELETE FROM proxies")

    # ── Simulations ───────────────────────────────────────────────────────────

    def create_simulation(self, name, server_id, secret,
                          interim_interval, term_time,
                          lcp_protocols: str = 'PAP') -> int:
        return self._exec("""
            INSERT INTO simulations
            (name,radius_server_id,secret,interim_update_interval,termination_time,lcp_protocols)
            VALUES(?,?,?,?,?,?)
        """, (name, server_id, secret, interim_interval, term_time, lcp_protocols), rowid=True)

    def add_cpe(self, sim_id, proxy_ip, proxy_port, username, password) -> int:
        return self._exec("""
            INSERT INTO simulation_cpes
            (simulation_id,proxy_ip,proxy_port,username,password)
            VALUES(?,?,?,?,?)
        """, (sim_id, proxy_ip, proxy_port, username, password), rowid=True)

    def get_simulations(self) -> List[Dict]:
        return self._exec(
            "SELECT * FROM simulations ORDER BY id DESC", all_=True)

    def get_simulation(self, sid: int) -> Optional[Dict]:
        return self._exec(
            "SELECT * FROM simulations WHERE id=?", (sid,), one=True)

    def get_cpes(self, sim_id: int) -> List[Dict]:
        return self._exec(
            "SELECT * FROM simulation_cpes WHERE simulation_id=?",
            (sim_id,), all_=True)

    def set_sim_status(self, sim_id: int, status: str):
        self._exec(
            "UPDATE simulations SET status=? WHERE id=?", (status, sim_id))

    def delete_simulation(self, sim_id: int):
        self._exec("DELETE FROM simulation_cpes WHERE simulation_id=?", (sim_id,))
        self._exec("DELETE FROM logs WHERE simulation_id=?", (sim_id,))
        self._exec("DELETE FROM simulations WHERE id=?", (sim_id,))

    # ── CPE state ─────────────────────────────────────────────────────────────

    def cpe_status(self, cpe_id: int, status: str):
        self._exec(
            "UPDATE simulation_cpes SET status=? WHERE id=?", (status, cpe_id))

    def cpe_session(self, cpe_id: int, session_id: str, framed_ip: str = None,
                    lcp_protocol: str = None):
        self._exec(
            "UPDATE simulation_cpes SET session_id=?,framed_ip=?,lcp_protocol=COALESCE(?,lcp_protocol) WHERE id=?",
            (session_id, framed_ip, lcp_protocol, cpe_id))

    def cpe_started(self, cpe_id: int):
        self._exec(
            "UPDATE simulation_cpes SET started_at=datetime('now','localtime') WHERE id=?",
            (cpe_id,))

    def cpe_updated(self, cpe_id: int, download_bytes: int = 0, upload_bytes: int = 0):
        self._exec(
            "UPDATE simulation_cpes SET last_update_at=datetime('now','localtime'), download_bytes=?, upload_bytes=? WHERE id=?",
            (download_bytes, upload_bytes, cpe_id))

    def cpe_ended(self, cpe_id: int, download_bytes: int = 0, upload_bytes: int = 0):
        self._exec(
            "UPDATE simulation_cpes SET ended_at=datetime('now','localtime'), download_bytes=?, upload_bytes=? WHERE id=?",
            (download_bytes, upload_bytes, cpe_id))

    def cpe_stats(self, sim_id: int) -> Dict:
        rows = self._exec("""
            SELECT status, COUNT(*) cnt FROM simulation_cpes
            WHERE simulation_id=? GROUP BY status
        """, (sim_id,), all_=True)
        out = {'total': 0}
        for r in (rows or []):
            out[r['status']] = r['cnt']
            out['total'] += r['cnt']
        return out

    def cpe_details(self, sim_id: int = None) -> List[Dict]:
        base = """
            SELECT sc.*, s.name sim_name FROM simulation_cpes sc
            JOIN simulations s ON sc.simulation_id=s.id
        """
        if sim_id:
            return self._exec(base + " WHERE sc.simulation_id=? ORDER BY sc.id",
                               (sim_id,), all_=True)
        return self._exec(base + " ORDER BY sc.simulation_id, sc.id", all_=True)

    def overall_stats(self, sim_id: int = None) -> Dict:
        sql = "SELECT status, COUNT(*) cnt FROM simulation_cpes"
        params = ()
        if sim_id:
            sql += " WHERE simulation_id=?"
            params = (sim_id,)
        sql += " GROUP BY status"
        rows = self._exec(sql, params, all_=True)
        out = {'total': 0}
        for r in (rows or []):
            out[r['status']] = r['cnt']
            out['total'] += r['cnt']
        return out

    # ── Logs ──────────────────────────────────────────────────────────────────

    def add_log(self, sim_id, cpe_id, level, msg, ptype=None):
        self._exec(
            "INSERT INTO logs(simulation_id,cpe_id,level,packet_type,message) "
            "VALUES(?,?,?,?,?)",
            (sim_id, cpe_id, level, ptype, msg))

    def get_logs(self, sim_id=None, level=None, limit=200) -> List[Dict]:
        conds, params = [], []
        if sim_id:
            conds.append("simulation_id=?")
            params.append(sim_id)
        if level:
            conds.append("level=?")
            params.append(level)
        where = ("WHERE " + " AND ".join(conds)) if conds else ""
        params.append(limit)
        return self._exec(
            f"SELECT * FROM logs {where} ORDER BY id DESC LIMIT ?",
            params, all_=True)

    def packet_stats(self, sim_id=None) -> List[Dict]:
        sql = ("SELECT packet_type, COUNT(*) qty FROM logs "
               "WHERE packet_type IS NOT NULL")
        params = ()
        if sim_id:
            sql += " AND simulation_id=?"
            params = (sim_id,)
        sql += " GROUP BY packet_type ORDER BY qty DESC"
        return self._exec(sql, params, all_=True)

    def clear_logs(self, sim_id=None):
        if sim_id:
            self._exec("DELETE FROM logs WHERE simulation_id=?", (sim_id,))
        else:
            self._exec("DELETE FROM logs")

    # ── Proxy test helpers ────────────────────────────────────────────────────

    def get_all_proxies(self) -> List[Dict]:
        """Retorna todos os proxies para teste em lote."""
        return self._exec(
            "SELECT * FROM proxies ORDER BY speed_ms ASC", all_=True)

    def delete_proxies_by_ids(self, ids: List[int]):
        """Remove proxies inativos pelo ID."""
        if not ids:
            return
        ph = ",".join("?" * len(ids))
        self._exec(f"DELETE FROM proxies WHERE id IN ({ph})", tuple(ids))

    def update_proxy_speed(self, proxy_id: int, speed_ms: float):
        """Atualiza latência medida do proxy."""
        self._exec(
            "UPDATE proxies SET speed_ms=? WHERE id=?",
            (round(speed_ms, 2), proxy_id),
        )