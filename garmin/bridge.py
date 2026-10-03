"""Garmin Connect bridge — a localhost-only sidecar for the Node MCP server.

Why a sidecar: the only maintained Garmin Connect client (python-garminconnect)
is Python, and its MFA flow keeps login state on a live client instance, so it
needs a long-running process rather than one-shot scripts.

Security model
  * Binds 127.0.0.1 on an OS-assigned port and prints "READY <port>" on stdout.
  * Every request must carry X-Bridge-Secret (random per boot, set by Node).
  * Never writes tokens to disk. Node owns persistence (encrypted at rest in
    SQLite); any response may carry a "tokens" field whenever the token set
    changed (login or auto-refresh) so Node can save it.
  * A login only replaces the active session once the account is verified to
    be the expected Garmin profile, so a stranger who reaches the sign-in page
    can never displace the owner's session.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import secrets
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from garminconnect import (
    Garmin,
    GarminConnectAuthenticationError,
    GarminConnectConnectionError,
    GarminConnectTooManyRequestsError,
)

logging.basicConfig(level=logging.WARNING, stream=sys.stderr, format="[garmin-bridge] %(levelname)s %(message)s")
log = logging.getLogger("garmin-bridge")

SECRET = os.environ.get("BRIDGE_SECRET", "")
if len(SECRET) < 32:
    print("BRIDGE_SECRET missing or too short", file=sys.stderr)
    sys.exit(2)

PENDING_TTL_S = 10 * 60
# Gentle pacing between Garmin calls inside one daily fetch.
CALL_GAP_S = float(os.environ.get("GARMIN_CALL_GAP_S", "0.4"))

_state_lock = threading.RLock()   # guards _active, _last_tokens, _pending
_api_lock = threading.Lock()      # serialises Garmin API traffic
_active: Garmin | None = None
_last_tokens: str | None = None
_pending: dict[str, tuple[Garmin, float, int | None]] = {}


class BridgeError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


# ---------------------------------------------------------------- helpers ---

def g(obj: Any, *path: Any) -> Any:
    """Safe nested getter: g(d, 'a', 0, 'b') -> d['a'][0]['b'] or None."""
    cur = obj
    for key in path:
        if isinstance(cur, dict):
            cur = cur.get(key)
        elif isinstance(cur, list) and isinstance(key, int) and -len(cur) <= key < len(cur):
            cur = cur[key]
        else:
            return None
        if cur is None:
            return None
    return cur


def num(value: Any) -> float | int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value
    return None


def tokens_if_changed() -> str | None:
    """Return the serialised token set if it changed since last reported."""
    global _last_tokens
    with _state_lock:
        if _active is None:
            return None
        try:
            current = _active.client.dumps()
        except Exception:
            return None
        if current != _last_tokens:
            _last_tokens = current
            return current
    return None


def identity(api: Garmin) -> dict[str, Any]:
    return {
        "profile_id": getattr(api, "profile_id", None),
        "display_name": getattr(api, "display_name", None),
        "full_name": getattr(api, "full_name", None),
    }


def require_active() -> Garmin:
    with _state_lock:
        if _active is None:
            raise BridgeError(401, "not_authenticated", "Garmin is not connected")
        return _active


def translate(exc: Exception) -> BridgeError:
    if isinstance(exc, BridgeError):
        return exc
    if isinstance(exc, GarminConnectTooManyRequestsError):
        return BridgeError(429, "rate_limited", "Garmin rate limited the request; try again later")
    if isinstance(exc, GarminConnectAuthenticationError):
        return BridgeError(401, "auth", "Garmin rejected the credentials or session")
    if isinstance(exc, GarminConnectConnectionError):
        return BridgeError(502, "garmin_unavailable", f"Garmin request failed: {str(exc)[:300]}")
    log.warning("unexpected error: %s", type(exc).__name__)
    return BridgeError(500, "internal", f"{type(exc).__name__}: {str(exc)[:300]}")


def _activate(api: Garmin, expected_profile_id: int | None) -> dict[str, Any]:
    """Make a freshly logged-in client the active session, if it is allowed."""
    global _active, _last_tokens
    who = identity(api)
    if expected_profile_id is not None and who["profile_id"] != expected_profile_id:
        raise BridgeError(403, "wrong_account", "This Garmin account is not the one this server is bound to")
    api.password = None
    with _state_lock:
        _active = api
        _last_tokens = None  # force the new token set out to Node
    return who


def _cleanup_pending() -> None:
    now = time.time()
    with _state_lock:
        for key in [k for k, (_, t, _) in _pending.items() if now - t > PENDING_TTL_S]:
            _pending.pop(key, None)


# --------------------------------------------------------------- handlers ---

def h_load(body: dict[str, Any]) -> dict[str, Any]:
    """Restore a saved token set (sent by Node at boot)."""
    global _active, _last_tokens
    tokens = body.get("tokens")
    if not isinstance(tokens, str) or not tokens:
        raise BridgeError(400, "bad_request", "tokens required")
    api = Garmin()
    api.client.loads(tokens)
    with _api_lock:
        api._load_profile_and_settings()  # also validates/refreshes the token
    with _state_lock:
        _active = api
        _last_tokens = tokens
    return {"status": "ok", "account": identity(api)}


def h_status(_: dict[str, Any]) -> dict[str, Any]:
    with _state_lock:
        api = _active
    return {"authenticated": api is not None, "account": identity(api) if api else None}


def h_login(body: dict[str, Any]) -> dict[str, Any]:
    email = body.get("email")
    password = body.get("password")
    expected = body.get("expected_profile_id")
    if not isinstance(email, str) or not isinstance(password, str) or not email or not password:
        raise BridgeError(400, "bad_request", "email and password required")
    if expected is not None and not isinstance(expected, int):
        raise BridgeError(400, "bad_request", "expected_profile_id must be an integer")
    _cleanup_pending()

    api = Garmin(email, password, return_on_mfa=True)
    status, _ = api.login()
    if status == "needs_mfa":
        pending_id = secrets.token_urlsafe(24)
        with _state_lock:
            _pending[pending_id] = (api, time.time(), expected)
        return {"status": "mfa_required", "pending_id": pending_id}

    # return_on_mfa mode skips the profile load on a clean login; do it here.
    api._load_profile_and_settings()
    return {"status": "ok", "account": _activate(api, expected)}


def h_login_mfa(body: dict[str, Any]) -> dict[str, Any]:
    pending_id = body.get("pending_id")
    code = body.get("code")
    if not isinstance(pending_id, str) or not isinstance(code, str):
        raise BridgeError(400, "bad_request", "pending_id and code required")
    code = code.strip().replace(" ", "")
    if not code.isdigit() or not 4 <= len(code) <= 10:
        raise BridgeError(400, "bad_code", "Enter the numeric code Garmin sent you")
    _cleanup_pending()
    with _state_lock:
        entry = _pending.get(pending_id)
    if entry is None:
        raise BridgeError(410, "expired", "Sign-in expired; start again")
    api, _, expected = entry
    try:
        api.resume_login({}, code)
    except GarminConnectAuthenticationError as exc:
        # Wrong code: the pending session stays usable for another try.
        raise BridgeError(401, "bad_code", "Garmin rejected that code") from exc
    with _state_lock:
        _pending.pop(pending_id, None)
    return {"status": "ok", "account": _activate(api, expected)}


def _readiness_pick(entries: Any) -> dict[str, Any] | None:
    if not isinstance(entries, list) or not entries:
        return entries if isinstance(entries, dict) else None
    morning = [e for e in entries if isinstance(e, dict) and e.get("inputContext") == "AFTER_WAKEUP_RESET"]
    pool = morning or [e for e in entries if isinstance(e, dict)]
    if not pool:
        return None
    return max(pool, key=lambda e: str(e.get("timestampLocal") or e.get("timestamp") or ""))


def _training_status_pick(ts: Any) -> dict[str, Any] | None:
    devices = g(ts, "mostRecentTrainingStatus", "latestTrainingStatusData")
    if not isinstance(devices, dict) or not devices:
        return None
    values = [v for v in devices.values() if isinstance(v, dict)]
    primary = [v for v in values if v.get("primaryTrainingDevice")]
    return (primary or values or [None])[0]


def normalise_daily(day: str, raw: dict[str, Any]) -> dict[str, Any]:
    def as_dict(value: Any) -> dict[str, Any]:
        return value if isinstance(value, dict) else {}

    s = as_dict(raw.get("summary"))
    d = as_dict(g(raw.get("sleep"), "dailySleepDTO"))
    h = as_dict(g(raw.get("hrv"), "hrvSummary"))
    r = as_dict(_readiness_pick(raw.get("readiness")))
    tsd = as_dict(_training_status_pick(raw.get("training_status")))
    vo2 = as_dict(g(raw.get("training_status"), "mostRecentVO2Max", "generic"))
    return {
        "date": day,
        # daily summary
        "steps": num(s.get("totalSteps")),
        "distance_m": num(s.get("totalDistanceMeters")),
        "resting_hr": num(s.get("restingHeartRate")),
        "min_hr": num(s.get("minHeartRate")),
        "max_hr": num(s.get("maxHeartRate")),
        "total_kcal": num(s.get("totalKilocalories")),
        "active_kcal": num(s.get("activeKilocalories")),
        "intensity_moderate_min": num(s.get("moderateIntensityMinutes")),
        "intensity_vigorous_min": num(s.get("vigorousIntensityMinutes")),
        "stress_avg": num(s.get("averageStressLevel")),
        "stress_max": num(s.get("maxStressLevel")),
        "bb_high": num(s.get("bodyBatteryHighestValue")),
        "bb_low": num(s.get("bodyBatteryLowestValue")),
        "bb_charged": num(s.get("bodyBatteryChargedValue")),
        "bb_drained": num(s.get("bodyBatteryDrainedValue")),
        "bb_wake": num(s.get("bodyBatteryAtWakeTime")),
        "spo2_avg": num(s.get("averageSpo2")),
        "spo2_low": num(s.get("lowestSpo2")),
        "resp_waking": num(s.get("avgWakingRespirationValue")),
        # last night's sleep (Garmin files it under the morning's date)
        "sleep_s": num(d.get("sleepTimeSeconds")),
        "deep_s": num(d.get("deepSleepSeconds")),
        "light_s": num(d.get("lightSleepSeconds")),
        "rem_s": num(d.get("remSleepSeconds")),
        "awake_s": num(d.get("awakeSleepSeconds")),
        "sleep_start_gmt": num(d.get("sleepStartTimestampGMT")),
        "sleep_end_gmt": num(d.get("sleepEndTimestampGMT")),
        "sleep_score": num(g(d, "sleepScores", "overall", "value")),
        "sleep_quality": g(d, "sleepScores", "overall", "qualifierKey"),
        "sleep_resp_avg": num(d.get("averageRespirationValue")),
        "sleep_stress_avg": num(d.get("avgSleepStress")),
        "sleep_spo2_avg": num(d.get("averageSpO2Value")),
        # HRV
        "hrv_last_night": num(h.get("lastNightAvg")),
        "hrv_5min_high": num(h.get("lastNight5MinHigh")),
        "hrv_weekly": num(h.get("weeklyAvg")),
        "hrv_status": h.get("status"),
        "hrv_baseline_low": num(g(h, "baseline", "balancedLow")),
        "hrv_baseline_high": num(g(h, "baseline", "balancedUpper")),
        # training readiness
        "readiness_score": num(r.get("score")),
        "readiness_level": r.get("level"),
        "readiness_feedback": r.get("feedbackShort"),
        "recovery_time_min": num(r.get("recoveryTime")),
        # training status / load
        "training_status": tsd.get("trainingStatusFeedbackPhrase"),
        "load_acute": num(g(tsd, "acuteTrainingLoadDTO", "dailyTrainingLoadAcute")),
        "load_chronic": num(g(tsd, "acuteTrainingLoadDTO", "dailyTrainingLoadChronic")),
        "acwr": num(g(tsd, "acuteTrainingLoadDTO", "dailyAcuteChronicWorkloadRatio")),
        "vo2max": num(vo2.get("vo2MaxPreciseValue")) or num(vo2.get("vo2MaxValue")),
    }


def h_daily(body: dict[str, Any]) -> dict[str, Any]:
    day = body.get("date")
    if not isinstance(day, str) or len(day) != 10:
        raise BridgeError(400, "bad_request", "date (YYYY-MM-DD) required")
    api = require_active()
    calls = {
        "summary": api.get_user_summary,
        "sleep": api.get_sleep_data,
        "hrv": api.get_hrv_data,
        "readiness": api.get_training_readiness,
        "training_status": api.get_training_status,
    }
    raw: dict[str, Any] = {}
    errors: dict[str, str] = {}
    with _api_lock:
        for i, (name, fn) in enumerate(calls.items()):
            if i:
                time.sleep(CALL_GAP_S)
            try:
                raw[name] = fn(day)
            except (GarminConnectAuthenticationError, GarminConnectTooManyRequestsError):
                raise
            except Exception as exc:  # one missing metric must not sink the day
                raw[name] = None
                errors[name] = f"{type(exc).__name__}: {str(exc)[:200]}"
    return {"date": day, "normalised": normalise_daily(day, raw), "raw": raw, "errors": errors}


def normalise_activity(a: dict[str, Any]) -> dict[str, Any]:
    return {
        "activity_id": a.get("activityId"),
        "name": a.get("activityName"),
        "type_key": g(a, "activityType", "typeKey"),
        "start_local": a.get("startTimeLocal"),
        "start_gmt": a.get("startTimeGMT"),
        "duration_s": num(a.get("duration")),
        "moving_s": num(a.get("movingDuration")),
        "distance_m": num(a.get("distance")),
        "avg_hr": num(a.get("averageHR")),
        "max_hr": num(a.get("maxHR")),
        "kcal": num(a.get("calories")),
        "aerobic_te": num(a.get("aerobicTrainingEffect")),
        "anaerobic_te": num(a.get("anaerobicTrainingEffect")),
        "training_load": num(a.get("activityTrainingLoad")),
        "avg_speed": num(a.get("averageSpeed")),
        "elevation_gain": num(a.get("elevationGain")),
        "z1_s": num(a.get("hrTimeInZone_1")),
        "z2_s": num(a.get("hrTimeInZone_2")),
        "z3_s": num(a.get("hrTimeInZone_3")),
        "z4_s": num(a.get("hrTimeInZone_4")),
        "z5_s": num(a.get("hrTimeInZone_5")),
    }


def h_activities(body: dict[str, Any]) -> dict[str, Any]:
    start, end = body.get("start"), body.get("end")
    if not isinstance(start, str) or not isinstance(end, str):
        raise BridgeError(400, "bad_request", "start and end (YYYY-MM-DD) required")
    api = require_active()
    with _api_lock:
        acts = api.get_activities_by_date(start, end) or []
    out = [
        {"normalised": normalise_activity(a), "raw": a}
        for a in acts
        if isinstance(a, dict) and a.get("activityId") is not None
    ]
    return {"activities": out}


ROUTES = {
    "/status": h_status,
    "/session/load": h_load,
    "/login": h_login,
    "/login/mfa": h_login_mfa,
    "/daily": h_daily,
    "/activities": h_activities,
}


class Handler(BaseHTTPRequestHandler):
    server_version = "garmin-bridge"

    def log_message(self, *_: Any) -> None:  # keep request lines (and bodies) out of logs
        return

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:  # noqa: N802
        if not hmac.compare_digest(self.headers.get("X-Bridge-Secret", ""), SECRET):
            self._send(401, {"error": "unauthorized"})
            return
        route = ROUTES.get(self.path)
        if route is None:
            self._send(404, {"error": "not_found"})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length) or b"{}") if length else {}
            if not isinstance(body, dict):
                raise BridgeError(400, "bad_request", "JSON object expected")
            result = route(body)
            tokens = tokens_if_changed()
            if tokens:
                result["tokens"] = tokens
            self._send(200, result)
        except Exception as exc:  # noqa: BLE001
            err = translate(exc)
            payload: dict[str, Any] = {"error": err.code, "message": err.message}
            tokens = tokens_if_changed()
            if tokens:
                payload["tokens"] = tokens
            self._send(err.status, payload)


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    print(f"READY {server.server_address[1]}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
