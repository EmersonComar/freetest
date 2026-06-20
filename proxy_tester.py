import socket
import threading
import time
from typing import Callable, Dict, List, Optional

import socks

# Alvo do teste — DNS público (confiável e rápido)
TEST_HOST    = "8.8.8.8"
TEST_PORT    = 53
DEF_TIMEOUT  = 8
DEF_WORKERS  = 50


def test_single_proxy(
    proxy_ip: str,
    proxy_port: int,
    timeout: int = DEF_TIMEOUT,
) -> Dict:
    """
    Testa um único proxy SOCKS5 tentando conexão TCP via tunnel.
    Retorna: {alive, latency_ms, error}
    """
    result = {
        "ip":         proxy_ip,
        "port":       proxy_port,
        "alive":      False,
        "latency_ms": None,
        "error":      None,
    }
    try:
        s = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
        s.set_proxy(socks.SOCKS5, proxy_ip, int(proxy_port))
        s.settimeout(timeout)
        t0 = time.monotonic()
        s.connect((TEST_HOST, TEST_PORT))
        result["latency_ms"] = round((time.monotonic() - t0) * 1000, 2)
        result["alive"] = True
        s.close()
    except Exception as e:
        result["error"] = str(e)[:120]
    return result


def test_proxy_batch(
    proxies: List[Dict],
    max_workers: int = DEF_WORKERS,
    timeout: int = DEF_TIMEOUT,
    on_progress: Optional[Callable[[int, int, Dict], None]] = None,
) -> Dict:
    """
    Testa múltiplos proxies concorrentemente com semáforo de controle.

    Args:
        proxies:      lista de dicts com 'id', 'ip', 'port'
        max_workers:  threads simultâneas
        timeout:      timeout por proxy (segundos)
        on_progress:  callback(completed, total, result_dict)

    Returns:
        {
            "alive":       [proxy_dict, ...],
            "dead":        [proxy_dict, ...],
            "alive_count": int,
            "dead_count":  int,
        }
    """
    alive: List[Dict] = []
    dead:  List[Dict] = []
    completed = [0]
    total     = len(proxies)
    lock      = threading.Lock()
    sem       = threading.Semaphore(max_workers)

    def _worker(proxy: Dict):
        with sem:
            res = test_single_proxy(proxy["ip"], proxy["port"], timeout)
        with lock:
            if res["alive"]:
                alive.append({**proxy, "speed_ms": res["latency_ms"]})
            else:
                dead.append(proxy)
            completed[0] += 1
            if on_progress:
                try:
                    on_progress(completed[0], total, res)
                except Exception:
                    pass

    threads = [
        threading.Thread(target=_worker, args=(p,), daemon=True)
        for p in proxies
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    return {
        "alive":       alive,
        "dead":        dead,
        "alive_count": len(alive),
        "dead_count":  len(dead),
    }