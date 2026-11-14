#!/usr/bin/env python3
"""User-level exit monitor. It terminates apps; it is NOT a network firewall."""
import argparse
import asyncio
import contextlib
from datetime import datetime, timezone
from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import plistlib
import re
import random
import shutil
import signal
import subprocess
import sys
import time
from typing import Optional

EXPECTED = "103.131.112.53"
INTERVAL = 3.0
TIMEOUT = 4.0
FRESH_FOR = INTERVAL + TIMEOUT + .2
LABEL = "local.taiwan-exit-watch"
HOME_DIR = Path.home()
BASE = HOME_DIR / "Library/Application Support/TaiwanExitWatch"
LOGS = HOME_DIR / "Library/Logs/TaiwanExitWatch"
PLIST = HOME_DIR / "Library/LaunchAgents" / (LABEL + ".plist")
ROOTS = ("/Applications/Claude.app/", "/Applications/ChatGPT.app/",
         str(HOME_DIR / ".local/share/claude/versions") + "/",
         str(HOME_DIR / ".codex/computer-use") + "/",
         str(HOME_DIR / "Library/Application Support/Codex") + "/",
         str(HOME_DIR / ".cache/codex-runtimes") + "/")
VERSION = "3.6-random-site-selection"
STATUS_INTERVAL = 2.0
LOG_FLUSH_INTERVAL = 10.0
APP_POLL_INTERVAL = 1.0
# Only sites verified on both paths within TIMEOUT are admitted.
SITES = (
    ("Cloudflare", "https://www.cloudflare.com/cdn-cgi/trace", "trace"),
    ("ident.me", "https://ident.me", "text"),
    ("ipify", "https://api.ipify.org", "text"),
    ("ping0", "https://ping0.cc/ip", "text"),
    ("Amazon", "https://checkip.amazonaws.com", "text"),
    ("icanhazip", "https://icanhazip.com", "text"),
    ("ifconfig.me", "https://ifconfig.me/ip", "text"),
    ("wtfismyip", "https://wtfismyip.com/text", "text"),
    ("IP.SB", "https://api.ip.sb/ip", "text"),
    ("ifconfig.io", "https://ifconfig.io/ip", "text"),
    ("myexternalip", "https://myexternalip.com/raw", "text"),
    ("ifconfig.tw", "https://ifconfig.tw/ip", "text"),
    ("ipaddress.ai", "https://ipaddress.ai/ip", "text"),
    ("ipconfig.is", "https://ipconfig.is/", "text"),
    ("eth0.me", "https://eth0.me/", "text"),
    ("ipaddress.sh", "https://ipaddress.sh/", "text"),
    ("ip.me", "https://ip.me/", "text"),
    ("wgetip.com", "https://wgetip.com/", "text"),
    ("IPIP0", "https://ipip0.net/en", "ipip0_html"),
    ("IPPure", "https://my.ippure.com/v1/info", "json_ip"),
    ("GeoJS", "https://get.geojs.io/v1/ip.json", "json_ip"),
    ("FreeIPAPI", "https://free.freeipapi.com/api/v1/json/", "json_ip_address"),
    ("ipaddress.fi", "https://ipaddress.fi/api/v1/my-ip?format=text", "text"),
    ("HTTPBin", "https://httpbin.org/ip", "json_origin"),
)
PHASE_SIZES = {"regular": 2, "recheck": 3, "extended": 5, "final": 3}


def select_recheck_sites(excluded, count=3):
    available = [site for site in SITES if site[0] not in excluded]
    if len(available) < count:
        raise ValueError("Recheck requires %d different additional websites" % count)
    return tuple(random.sample(available, count))


@dataclass
class ProbeRound:
    epoch: int
    seq: int
    sites: tuple
    mode: str
    phase: str = "regular"
    trigger_seq: Optional[int] = None
    excluded_sites: tuple = ()
    started: Optional[float] = None
    results: dict = field(default_factory=dict)


def select_pair(sequence):
    # Each draw is independent; a website may appear again in the next round.
    sites = tuple(random.sample(SITES, 2))
    mode = "default_route" if sequence % 2 else "nextin_proxy"
    return sites, mode


class State:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.epoch = 0
        self.last_seq = -1
        self.last_completed = None
        self.reason = "starting_waiting_for_two_sites"
        self.results = []
        self.path = None
        self.path_rounds = {}
        self.alerts = {}
        self.alert_sequence = 0

    def invalidate(self, reason):
        self.epoch += 1
        self.last_completed = None
        self.reason = reason
        self.results = []
        self.path_rounds = {}
        # Discard in-flight samples, but a risk already confirmed must still
        # cause one stop attempt even if the network changes before discovery.

    def request_close(self, mode, seq, reason, results):
        previous = self.alerts.get(mode)
        if previous and previous["seq"] >= seq:
            return
        self.alert_sequence += 1
        self.alerts[mode] = {"token": self.alert_sequence, "seq": seq, "reason": reason,
                             "results": results, "completed": self.clock()}

    def observe_mismatch(self, epoch, seq, started, result, mode):
        if (epoch != self.epoch or self.clock() - started >= FRESH_FOR
                or result.get("outcome") != "exit_mismatch"):
            return False
        self.request_close(mode, seq, "exit_mismatch", [result])
        return True

    def acknowledge_close(self, tokens):
        for mode, token in tokens.items():
            if mode in self.alerts and self.alerts[mode]["token"] == token:
                del self.alerts[mode]

    def result(self, epoch, seq, started, results, mode, phase="regular"):
        previous = self.path_rounds.get(mode)
        expected_count = PHASE_SIZES[phase]
        # Five sites occupy three dispatch slots; allow the final slot its full timeout.
        window = FRESH_FOR + ((expected_count - 1) // 2) * INTERVAL
        if (epoch != self.epoch or (previous and seq <= previous["seq"])
                or self.clock() - started >= window):
            return False
        if len(results) != expected_count or len({r["site"] for r in results}) != expected_count:
            raise ValueError("A decision requires %d distinct websites" % expected_count)
        self.last_seq = seq
        self.last_completed = self.clock()
        self.results = results
        self.path = mode
        good = sum(item["ok"] for item in results)
        mismatch = any(item.get("outcome") == "exit_mismatch" for item in results)
        if mismatch:
            reason = "exit_mismatch"
            self.request_close(mode, seq, reason, results)
        elif good == 0:
            reason = {"regular": "awaiting_three_site_recheck",
                      "recheck": "awaiting_five_site_verification",
                      "extended": "awaiting_final_three_site_verification",
                      "final": "final_three_verification_failed"}[phase]
            if phase == "final":
                self.request_close(mode, seq, reason, results)
        else:
            reason = "verified" if good == expected_count else "one_site_ok"
        self.path_rounds[mode] = {"seq": seq, "completed": self.last_completed,
                                 "results": results, "good": good, "phase": phase, "reason": reason}
        self.reason = reason
        return True

    def fresh(self):
        return self.last_completed is not None and 0 <= self.clock() - self.last_completed < FRESH_FOR

    def should_close(self):
        # A healthy proxy result cannot erase a failed default-path pair (or
        # vice versa); recovery and ordering are evaluated separately per path.
        return bool(self.alerts) or any(item["reason"] in ("exit_mismatch", "final_three_verification_failed")
                                       and 0 <= self.clock() - item["completed"] < FRESH_FOR
                                       for item in self.path_rounds.values())

    def close_reason(self):
        reasons = [item["reason"] for item in self.alerts.values()]
        reasons += [item["reason"] for item in self.path_rounds.values()
                    if 0 <= self.clock() - item["completed"] < FRESH_FOR]
        return "exit_mismatch" if "exit_mismatch" in reasons else "final_three_verification_failed"

    def status(self):
        good = sum(item["ok"] for item in self.results)
        return {"exit_confirmed": self.fresh() and good > 0 and not self.should_close(),
                "close_apps": self.should_close(),
                "reason": self.close_reason() if self.should_close() else
                          (self.reason if self.fresh() or not self.results else "waiting_for_fresh_pair"),
                "results": self.results, "path": self.path, "round": self.last_seq,
                "path_rounds": self.path_rounds,
                "alerts": self.alerts,
                "expected_exit": EXPECTED, "mode": "two_three_five_three_site_verification_no_firewall",
                "version": VERSION, "site_pool_size": len(SITES),
                "site_selection": "random_without_replacement_within_round_or_recheck_chain",
                "requests_per_second": 2 / INTERVAL, "interval_seconds": INTERVAL, "timeout_seconds": TIMEOUT,
                "updated_at": time.time(), "pid": os.getpid()}


class BatchLogHandler(logging.Handler):
    """Batch ordinary records; risk and lifecycle evidence bypass the timer."""
    def __init__(self, path):
        super().__init__()
        self.sink = RotatingFileHandler(path, maxBytes=5 * 1048576, backupCount=5)
        self.sink.setFormatter(logging.Formatter("%(message)s"))
        self.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        self.pending = []
        self.last_flush = time.monotonic()

    def emit(self, record):
        self.pending.append(self.format(record))
        urgent = record.levelno >= logging.ERROR or record.getMessage().startswith(
            ("exit_mismatch", "apps_", "close_attempt", "monitor_", "topology_"))
        if urgent or len(self.pending) >= 256:
            self.flush()

    def flush(self):
        self.acquire()
        try:
            if self.pending:
                record = logging.LogRecord("exitwatch", logging.INFO, "", 0,
                                           "\n".join(self.pending), (), None)
                self.sink.emit(record)
                self.pending.clear()
            self.last_flush = time.monotonic()
        finally:
            self.release()

    def close(self):
        self.flush()
        self.sink.close()
        super().close()


class StatusPublisher:
    def __init__(self):
        self.last_write = -float("inf")
        self.last_risk = None

    def publish(self, value, now):
        risk = (value.get("close_apps"), value.get("reason") if value.get("close_apps") else None)
        if now - self.last_write >= STATUS_INTERVAL or risk != self.last_risk:
            write_status(value)
            self.last_write, self.last_risk = now, risk


def app_snapshot(table):
    selected = targets(table)
    groups = {"Claude": [], "Codex": []}
    for pid in sorted(selected):
        item = table[pid]
        if item["ppid"] in selected:
            continue
        app = "Claude" if (item["path"].startswith(ROOTS[0]) or item["path"].startswith(ROOTS[2])) else "Codex"
        groups[app].append({"pid": pid, "birth": item["birth"], "path": item["path"]})
    return {name: {"running": bool(roots), "roots": roots} for name, roots in groups.items()}


class CommandError(RuntimeError):
    def __init__(self, code, detail):
        self.code = code
        super().__init__("command_exit=%s: %s" % (code, detail))


async def output(args, timeout=TIMEOUT + .3):
    process = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE,
                                                  stderr=asyncio.subprocess.PIPE)
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout)
    except asyncio.TimeoutError:
        if process.returncode is None:
            process.kill()
        await process.communicate()
        raise TimeoutError("Process exceeded %.1f seconds" % timeout) from None
    except BaseException:
        if process.returncode is None:
            process.kill()
        await process.communicate()
        raise
    if process.returncode:
        raise CommandError(process.returncode, stderr.decode(errors="replace")[:800] or "command failed")
    return stdout.decode(errors="replace")


async def probe(site, mode):
    name, url, kind = site
    limit = "131072" if kind == "ipip0_html" else "8192"
    args = ["/usr/bin/curl", "--silent", "--show-error", "--fail", "--max-filesize", limit,
            "--user-agent", "curl/8.7.1 TaiwanExitWatch/2.0",
            "--header", "Cache-Control: no-cache",
            "--connect-timeout", str(TIMEOUT), "--max-time", str(TIMEOUT), "--proto", "=https"]
    if mode == "default_route":
        args += ["--noproxy", "*"]
    elif mode == "nextin_proxy":
        args += ["--noproxy", "", "--proxy", "http://[::1]:7890"]
    else:
        raise ValueError("Unknown probe mode")
    body = await output(args + [url])
    if kind == "trace":
        values = re.findall(r"^ip=(.+)$", body, re.M)
        if len(values) != 1:
            raise ValueError("Response does not contain exactly one ip= field")
        value = values[0]
    elif kind in ("json_ip", "json_ip_address", "json_origin"):
        field = {"json_ip": "ip", "json_ip_address": "ipAddress", "json_origin": "origin"}[kind]
        data = json.loads(body)
        if not isinstance(data, dict) or "error" in data or data.get("success") is False:
            raise ValueError("IP API returned an error or an invalid object")
        value = data[field]
        if not isinstance(value, str):
            raise ValueError("JSON IP field must be a string")
        # An origin list is ambiguous; never choose one address from a chain.
        # The common ip_address validation below rejects lists and other text.
    elif kind == "ipip0_html":
        # Read only the server's prefilled visitor-IP field on an unparameterized
        # GET. Do not treat queried-IP results, ads or other HTML IPs as evidence.
        class VisitorIP(HTMLParser):
            def __init__(self):
                super().__init__()
                self.values = []

            def handle_starttag(self, tag, attrs):
                attrs = dict(attrs)
                if tag == "input" and attrs.get("id") == "query-input" and attrs.get("name") == "query":
                    self.values.append(attrs.get("value", ""))
        parser = VisitorIP()
        parser.feed(body)
        if len(parser.values) != 1:
            raise ValueError("IPIP0 page must contain exactly one visitor-IP input")
        value = parser.values[0]
    else:
        value = body.strip()
    import ipaddress
    return str(ipaddress.ip_address(value))


async def probe_result(site, mode):
    started = time.monotonic()
    result = {"site": site[0], "url": site[1], "path": mode, "ok": False}
    try:
        address = await probe(site, mode)
        result.update(ip=address, ok=address == EXPECTED,
                      outcome="expected_exit" if address == EXPECTED else "exit_mismatch")
    except Exception as exc:
        result.update(outcome="probe_failed", error_type=type(exc).__name__,
                      error=str(exc)[:800], command_exit=getattr(exc, "code", None))
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000)
    return result


async def topology():
    listing, route = await asyncio.gather(output(["/usr/sbin/scutil", "--nc", "list"]),
                                           output(["/sbin/route", "-n", "get", "1.1.1.1"]))
    service = re.search(r"\(Connected\)\s+([A-Fa-f0-9-]+) VPN \(com\.Tommy\.Nextin\)", listing)
    if not service:
        raise RuntimeError("Nextin disconnected")
    status = await output(["/usr/sbin/scutil", "--nc", "status", service[1]])
    interface = re.search(r"InterfaceName\s*:\s*(utun\d+)", status)
    routed = re.search(r"interface:\s*(\S+)", route)
    if not interface or not routed or interface[1] != routed[1]:
        raise RuntimeError("Nextin is not the default route")
    pids = (await output(["/usr/bin/pgrep", "-x", "ProxyTunnel"])).split()
    return (service[1], interface[1], tuple(pids))


def process_table():
    result = subprocess.run(["/bin/ps", "-axo", "uid=,pid=,ppid=,lstart=,comm="],
                            capture_output=True, text=True, timeout=2, check=True)
    table = {}
    for line in result.stdout.splitlines():
        fields = line.strip().split(None, 8)
        if len(fields) == 9 and all(value.isdigit() for value in fields[:3]) and int(fields[0]) == os.getuid():
            table[int(fields[1])] = {"ppid": int(fields[2]), "birth": tuple(fields[3:8]), "path": fields[8]}
    return table


def targets(table):
    selected = {pid for pid, item in table.items() if item["path"].startswith(ROOTS)}
    while True:
        new = {pid for pid, item in table.items() if item["ppid"] in selected}
        if new <= selected:
            return selected
        selected.update(new)


async def stop_apps(should_close):
    # Process discovery can stall; keep network probes running while it does.
    snapshot = await asyncio.to_thread(process_table)
    selected = targets(snapshot)
    if not selected or not should_close():
        return []
    current = await asyncio.to_thread(process_table)
    confirmed = [pid for pid in selected if pid in current
                 and current[pid]["birth"] == snapshot[pid]["birth"]
                 and current[pid]["path"] == snapshot[pid]["path"]]
    # A later healthy pair, route change or expired evidence cancels this stop.
    if not should_close():
        return []
    # Stop every selected process before killing parents, so descendants cannot
    # keep sending while their parent is being terminated. This cannot retract
    # packets already queued in the kernel or sent onto the network.
    logging.warning("apps_close_targets=%s", json.dumps(
        [{"pid": pid, **current[pid]} for pid in confirmed], ensure_ascii=False))
    for sig in (signal.SIGSTOP, signal.SIGKILL):
        delivered, gone = [], []
        try:
            for pid in confirmed:
                try:
                    os.kill(pid, sig)
                    delivered.append(pid)
                except ProcessLookupError:
                    gone.append(pid)
        finally:
            # Delivery is not proof of exit; the process observer logs subsequent absence.
            logging.warning("apps_signal signal=%s delivered=%s already_gone=%s", sig.name, delivered, gone)
    return confirmed


def write_status(value):
    LOGS.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = LOGS / "status.json"
    temporary = LOGS / ("status.%d.tmp" % os.getpid())
    temporary.write_text(json.dumps(value, ensure_ascii=False, separators=(",", ":")))
    temporary.replace(path)


class Monitor:
    def __init__(self):
        self.state = State()
        self.sequence = 0
        self.topology_ok = False
        self.current_topology = None
        self.topology_observed_at = None
        self.topology_error = None
        self.checks = set()
        self.rotation = 0
        self.rechecks = {}
        self.recheck_queue = deque()
        self.apps_observed = {"observed_at": None, "apps": None}
        self.app_fingerprint = None
        self.app_heartbeat = -float("inf")
        self.last_close_audit = None
        self.publisher = StatusPublisher()

    def apps_evidence(self):
        observed = self.apps_observed
        apps = observed.get("apps")
        return {"observed_at": observed["observed_at"],
                "apps": None if apps is None else {name: {"running": group["running"],
                         "root_pids": [item["pid"] for item in group["roots"]]}
                         for name, group in apps.items()}}

    def queue_recheck(self, original):
        active = self.rechecks.get(original.mode)
        if (original.epoch != self.state.epoch or original.phase == "final"
                or (active is not None and active is not original)):
            return
        phase = {"regular": "recheck", "recheck": "extended", "extended": "final"}[original.phase]
        excluded = set(original.excluded_sites) | {site[0] for site in original.sites}
        self.sequence += 1
        sites = select_recheck_sites(excluded, PHASE_SIZES[phase])
        batch = ProbeRound(original.epoch, self.sequence, sites, original.mode,
                           phase=phase, trigger_seq=original.seq, excluded_sites=tuple(sorted(excluded)))
        self.rechecks[batch.mode] = batch
        self.recheck_queue.extend((batch, site) for site in sites)
        logging.warning("recheck_queued round=%s trigger_round=%s path=%s phase=%s sites=%s",
                        batch.seq, original.seq, batch.mode, phase, [site[0] for site in sites])

    async def check_site(self, batch, site):
        started = time.monotonic()
        started_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        observed_topology = {"connected_and_default_route": self.topology_ok,
                             "interface": self.current_topology[1] if self.current_topology else None,
                             "observed_at": self.topology_observed_at,
                             "epoch": self.state.epoch}
        if batch.started is None:
            batch.started = started
        apps_at_start = self.apps_evidence()
        result = await probe_result(site, batch.mode)
        result.update(started_at=started_at, completed_at=datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                      topology_at_start=observed_topology, topology_epoch_at_completion=self.state.epoch,
                      apps_at_start=apps_at_start, apps_at_completion=self.apps_evidence())
        # A concrete wrong IP acts immediately, even while the other sites wait.
        if self.state.observe_mismatch(batch.epoch, batch.seq, started, result, batch.mode):
            logging.warning("exit_mismatch round=%s phase=%s result=%s", batch.seq, batch.phase,
                            json.dumps(result, ensure_ascii=False))
        batch.results[site[0]] = result
        if len(batch.results) != len(batch.sites):
            return
        results = [batch.results[s[0]] for s in batch.sites]
        if self.state.result(batch.epoch, batch.seq, batch.started, results, batch.mode, batch.phase):
            good = sum(item["ok"] for item in results)
            logging.info("round=%s path=%s sites=%s good=%s/%s phase=%s action=%s reason=%s",
                         batch.seq, batch.mode, [item["site"] for item in results], good,
                         len(results), batch.phase, "close_apps" if self.state.should_close()
                         else "keep_running", self.state.reason)
            logging.log(logging.WARNING if good < len(results) else logging.INFO,
                        "round_details=%s", json.dumps({"round": batch.seq,
                        "phase": batch.phase, "trigger_round": batch.trigger_seq,
                        "results": results}, ensure_ascii=False))
            if batch.phase != "final" and good == 0 and not any(
                    r.get("outcome") == "exit_mismatch" for r in results):
                self.queue_recheck(batch)
        if batch.phase != "regular" and self.rechecks.get(batch.mode) is batch:
            del self.rechecks[batch.mode]

    async def check(self, epoch, seq, started, sites=None, mode=None):
        if sites is None:
            sites, mode = select_pair(seq)
        self.sequence = max(self.sequence, seq)
        batch = ProbeRound(epoch, seq, tuple(sites), mode, started=started)
        await asyncio.gather(*(self.check_site(batch, site) for site in sites))

    def dispatch(self):
        # All regular AND recheck HTTP requests share this one two-request slot.
        jobs = []
        while self.recheck_queue and len(jobs) < 2:
            batch, site = self.recheck_queue.popleft()
            if batch.epoch == self.state.epoch:
                jobs.append((batch, site))
        if not jobs:
            # Finish staged verification before opening another normal
            # round; a newer round must not hide this recheck's conclusion.
            if self.rechecks:
                return []
            self.rotation += 1
            self.sequence += 1
            sites, mode = select_pair(self.rotation)
            batch = ProbeRound(self.state.epoch, self.sequence, sites, mode)
            jobs = [(batch, site) for site in sites]
        tasks = []
        for batch, site in jobs:
            task = asyncio.create_task(self.check_site(batch, site))
            self.checks.add(task)
            task.add_done_callback(self.completed)
            tasks.append(task)
        return tasks

    def invalidate(self, reason):
        logging.info("topology_epoch_changed reason=%s old_epoch=%s new_epoch=%s", reason,
                     self.state.epoch, self.state.epoch + 1)
        self.state.invalidate(reason)
        self.recheck_queue.clear()
        self.rechecks.clear()

    def status(self):
        value = self.state.status()
        value["apps_observed"] = self.apps_observed
        value["status_write_interval_seconds"] = STATUS_INTERVAL
        value["log_flush_interval_seconds"] = LOG_FLUSH_INTERVAL
        value["pending_rechecks"] = {mode: {"round": batch.seq, "trigger_round": batch.trigger_seq,
                                          "phase": batch.phase,
                                          "sites": [site[0] for site in batch.sites],
                                          "completed_sites": len(batch.results)}
                                     for mode, batch in self.rechecks.items()}
        if self.rechecks:
            value["exit_confirmed"] = False
        return value

    def completed(self, task):
        self.checks.discard(task)
        if not task.cancelled() and task.exception() is not None:
            logging.error("probe task failed without an exit decision: %r", task.exception())

    async def exit_loop(self):
        while True:
            self.dispatch()
            # Rechecks replace normal slots; never send a catch-up burst.
            await asyncio.sleep(INTERVAL)

    async def topology_loop(self):
        while True:
            try:
                current = await topology()
                self.topology_observed_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
                if current != self.current_topology:
                    self.invalidate("network_changed_waiting_for_pair")
                    logging.info("topology_observed connected_and_default_route=true interface=%s", current[1])
                self.current_topology, self.topology_ok = current, True
                self.topology_error = None
            except Exception as exc:
                self.topology_observed_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
                error = "%s: %s" % (type(exc).__name__, str(exc)[:300])
                if self.topology_ok or self.topology_error != error:
                    logging.warning("topology_observed connected_and_default_route=false error=%s", error)
                self.topology_error = error
                if self.topology_ok:
                    self.invalidate("tunnel_unavailable_waiting_for_pair")
                self.current_topology, self.topology_ok = None, False
            await asyncio.sleep(.5)

    async def apps_loop(self):
        while True:
            try:
                snapshot = app_snapshot(await asyncio.to_thread(process_table))
                observed = {"observed_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                            "apps": snapshot}
                fingerprint = json.dumps(snapshot, sort_keys=True)
                now = time.monotonic()
                if fingerprint != self.app_fingerprint or now - self.app_heartbeat >= 60:
                    event = "apps_state_changed" if self.app_fingerprint is not None and fingerprint != self.app_fingerprint else "apps_state_snapshot"
                    logging.info("%s=%s", event, json.dumps(observed, ensure_ascii=False))
                    self.app_heartbeat = now
                self.app_fingerprint = fingerprint
                self.apps_observed = observed
            except (OSError, subprocess.SubprocessError):
                self.apps_observed = {"observed_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                                      "apps": None, "error": "process_discovery_failed"}
                logging.exception("apps_observation_failed")
            await asyncio.sleep(APP_POLL_INTERVAL)

    async def log_flush_loop(self):
        while True:
            for handler in logging.getLogger().handlers:
                if isinstance(handler, BatchLogHandler) and time.monotonic() - handler.last_flush >= LOG_FLUSH_INTERVAL:
                    handler.flush()
            await asyncio.sleep(1)

    async def safety_loop(self):
        while True:
            if self.state.should_close():
                tokens = {mode: alert["token"] for mode, alert in self.state.alerts.items()}
                reason = self.state.close_reason()
                try:
                    killed = await stop_apps(self.state.should_close)
                except (OSError, subprocess.SubprocessError):
                    logging.exception("process discovery or stop failed")
                    killed = []
                else:
                    self.state.acknowledge_close(tokens)
                audit_key = (reason, tuple(sorted(tokens.items())), tuple(killed))
                if audit_key != self.last_close_audit:
                    logging.warning("close_attempt reason=%s target_pids=%s latest_apps_observation=%s", reason, killed,
                                    json.dumps(self.apps_observed, ensure_ascii=False))
                    self.last_close_audit = audit_key
                if killed:
                    logging.warning("apps stopped: reason=%s pids=%s", reason, killed)
            self.publisher.publish(self.status(), time.monotonic())
            await asyncio.sleep(.25)

    async def run(self):
        # Startup, topology changes and stale results do not independently close
        # apps. A wrong IP or a failed final three-site check can do that.
        loop = asyncio.get_running_loop()
        task = asyncio.current_task()
        loop.add_signal_handler(signal.SIGTERM, task.cancel)
        tasks = [asyncio.create_task(coro()) for coro in
                 (self.apps_loop, self.exit_loop, self.topology_loop, self.safety_loop, self.log_flush_loop)]
        try:
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
            raise RuntimeError("Monitor loop stopped")
        finally:
            for task in tasks + list(self.checks):
                task.cancel()
            await asyncio.gather(*tasks, *self.checks, return_exceptions=True)


def log_control(event, **details):
    LOGS.mkdir(mode=0o700, parents=True, exist_ok=True)
    handler = RotatingFileHandler(LOGS / "control.log", maxBytes=1048576, backupCount=2)
    handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    try:
        handler.emit(logging.LogRecord("control", logging.INFO, "", 0,
                     json.dumps(dict(event=event, **details), ensure_ascii=False), (), None))
    finally:
        handler.close()


def install():
    BASE.mkdir(mode=0o700, parents=True, exist_ok=True)
    if Path(__file__).resolve() != BASE / "watch.py":
        shutil.copyfile(__file__, BASE / "watch.py")
    (BASE / "watch.py").chmod(0o700)
    LOGS.mkdir(mode=0o700, parents=True, exist_ok=True)
    PLIST.parent.mkdir(parents=True, exist_ok=True)
    # Prepared, but disabled until the user runs Start.command.
    config = {"Label": LABEL, "ProgramArguments": ["/usr/bin/python3", str(BASE / "watch.py"), "run"],
              "RunAtLoad": True, "KeepAlive": True, "ThrottleInterval": 1,
              "StandardOutPath": str(LOGS / "launch.log"), "StandardErrorPath": str(LOGS / "launch.log")}
    PLIST.write_bytes(plistlib.dumps(config))
    PLIST.chmod(0o600)
    subprocess.run(["/bin/launchctl", "disable", "gui/%d/%s" % (os.getuid(), LABEL)], check=True)
    print("脚本已安装，尚未启动；不会修改网络设置。")


def start():
    log_control("monitor_start_requested")
    if not PLIST.exists():
        install()
    domain = "gui/%d" % os.getuid()
    subprocess.run(["/bin/launchctl", "enable", domain + "/" + LABEL], check=True)
    loaded = subprocess.run(["/bin/launchctl", "print", domain + "/" + LABEL], capture_output=True)
    if loaded.returncode:
        subprocess.run(["/bin/launchctl", "bootstrap", domain, str(PLIST)], check=True)
    log_control("monitor_start_command_completed")
    print("检测已启动并设为登录自启。每三秒最多两个请求；错误 IP 立即关闭，超时按 2→3→5→3 个网站验证。")


def stop():
    log_control("monitor_stop_requested")
    service = "gui/%d/%s" % (os.getuid(), LABEL)
    subprocess.run(["/bin/launchctl", "disable", service], check=True)
    result = subprocess.run(["/bin/launchctl", "bootout", service], capture_output=True)
    log_control("monitor_stop_command_completed", bootout_code=result.returncode)
    write_status({"running": False, "reason": "stopped_by_user", "updated_at": time.time()})
    print("检测已停止，登录自启已关闭；网络设置未变。")


async def check_once():
    monitor = Monitor()
    await monitor.check(0, 1, time.monotonic())
    # Use the same overlapping dispatch cadence as the service. Awaiting each
    # two-request batch separately would make the final three-site group stale.
    while monitor.rechecks and not monitor.state.should_close():
        await asyncio.sleep(INTERVAL)
        if monitor.rechecks and not monitor.state.should_close():
            monitor.dispatch()
    await asyncio.gather(*list(monitor.checks))
    print(json.dumps(dict(monitor.status(), apps_closed=False), ensure_ascii=False, indent=2))
    return not monitor.state.should_close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["install", "start", "stop", "status", "check", "run", "uninstall"])
    action = parser.parse_args().action
    if action == "run":
        LOGS.mkdir(mode=0o700, parents=True, exist_ok=True)
        handler = BatchLogHandler(LOGS / "watch.log")
        logging.basicConfig(level=logging.INFO, handlers=[handler])
        logging.info("monitor_started pid=%s status_write_seconds=2 log_batch_seconds=10 app_poll_seconds=1 version=%s sites=%s interval_seconds=%s requests_per_second=%s timeout=%s site_selection=random policy=mismatch_or_two_three_five_three_site_verification",
                     os.getpid(), VERSION, len(SITES), INTERVAL, 2 / INTERVAL, TIMEOUT)
        monitor = Monitor()
        try:
            asyncio.run(monitor.run())
        except (KeyboardInterrupt, asyncio.CancelledError):
            logging.info("monitor_stopped reason=termination_signal pid=%s", os.getpid())
        except BaseException:
            logging.exception("monitor_failed pid=%s", os.getpid())
            # An internal exception is not a completed final three-site verification.
            write_status({"exit_confirmed": False, "close_apps": False,
                          "reason": "monitor_failed", "updated_at": time.time()})
            raise
        finally:
            handler.flush()
    elif action == "check":
        raise SystemExit(0 if asyncio.run(check_once()) else 1)
    elif action == "status":
        path = LOGS / "status.json"
        print(path.read_text() if path.exists() else "检测尚未启动。")
    elif action == "uninstall":
        stop()
        PLIST.unlink(missing_ok=True)
        if BASE.exists():
            shutil.rmtree(BASE)
        print("脚本已卸载，日志保留。")
    else:
        globals()[action]()


if __name__ == "__main__":
    main()
