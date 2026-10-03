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
import re
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
    exercises,
)
from garminconnect.workout import (
    ConditionType,
    ExecutableStep,
    RunningWorkout,
    SportType,
    StepType,
    StrengthWorkout,
    TargetType,
    WorkoutSegment,
    create_repeat_group,
    create_strength_set,
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


# ------------------------------------------------------------- workouts ---
#
# Every write takes "dry_run": when true the request is fully validated and
# built (exercise names resolved, steps assembled) and a human-readable preview
# is returned, but nothing is sent to Garmin. Node maps the tools' `confirm`
# flag onto this, so a write always has a preview step before it happens.

DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
PACE_RE = re.compile(r"^(\d{1,2}):([0-5]\d)$")
NO_TARGET = {"workoutTargetTypeId": TargetType.NO_TARGET, "workoutTargetTypeKey": "no.target", "displayOrder": 1}
RUN_STEP_TYPES = {
    "warmup": (StepType.WARMUP, "warmup", 1),
    "cooldown": (StepType.COOLDOWN, "cooldown", 2),
    "interval": (StepType.INTERVAL, "interval", 3),
    "recovery": (StepType.RECOVERY, "recovery", 4),
    "rest": (StepType.REST, "rest", 5),
}
MAX_STEPS = 60


def _date(value: Any, field: str) -> str:
    if not isinstance(value, str) or not DATE_RE.match(value):
        raise BridgeError(400, "bad_request", f"{field} must be YYYY-MM-DD")
    return value


def _pos_int(value: Any, field: str, lo: int = 1, hi: int = 10**12) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or int(value) != value or not lo <= int(value) <= hi:
        raise BridgeError(400, "bad_request", f"{field} must be a whole number between {lo} and {hi}")
    return int(value)


def _pos_num(value: Any, field: str, lo: float, hi: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not lo <= float(value) <= hi:
        raise BridgeError(400, "bad_request", f"{field} must be a number between {lo} and {hi}")
    return float(value)


def _fmt_secs(s: float) -> str:
    s = int(round(s))
    return f"{s // 60}:{s % 60:02d}" if s < 3600 else f"{s // 3600}h{(s % 3600) // 60:02d}"


def _norm(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


_EX_BY_NORM: dict[str, dict[str, str]] = {}
for _e in exercises.EXERCISES:
    _EX_BY_NORM.setdefault(_norm(_e["name"]), _e)


def _resolve_exercise(name: Any) -> dict[str, str]:
    """Match a name to Garmin's catalogue, ignoring case, hyphens and spacing
    ("pull ups" -> "Pull-up"). Ambiguous or unknown names raise with
    suggestions instead of guessing."""
    if not isinstance(name, str) or not name.strip():
        raise BridgeError(400, "bad_request", "each exercise needs a name")
    raw = name.strip()
    key = _norm(raw)
    for candidate in (key, key[:-1] if key.endswith("s") else None, key[:-2] if key.endswith("es") else None):
        if candidate and candidate in _EX_BY_NORM:
            return _EX_BY_NORM[candidate]
    stem = key[:-1] if key.endswith("s") else key
    matches = sorted((e for k, e in _EX_BY_NORM.items() if stem and stem in k), key=lambda e: len(e["name"]))
    if len(matches) == 1:
        return matches[0]
    if matches:
        names = ", ".join(m["name"] for m in matches[:8])
        raise BridgeError(400, "ambiguous_exercise", f'"{raw}" matches several Garmin exercises: {names}. Use one of these names.')
    words = [w for w in re.split(r"\W+", raw) if len(w) > 3]
    near: list[str] = []
    for w in words:
        near.extend(sorted((e["name"] for e in exercises.find(w)), key=len)[:4])
    hint = f" Closest: {', '.join(dict.fromkeys(near))}." if near else ""
    raise BridgeError(400, "unknown_exercise", f'"{raw}" is not in Garmin\'s exercise catalogue.{hint}')


def _build_strength(body: dict[str, Any]) -> tuple[StrengthWorkout, list[str]]:
    items = body.get("exercises")
    if not isinstance(items, list) or not items:
        raise BridgeError(400, "bad_request", "exercises must be a non-empty list")
    if len(items) > 25:
        raise BridgeError(400, "bad_request", "at most 25 exercises per workout")
    steps: list[Any] = []
    lines: list[str] = []
    order = 1
    for i, item in enumerate(items, 1):
        if not isinstance(item, dict):
            raise BridgeError(400, "bad_request", f"exercise {i} must be an object")
        ex = _resolve_exercise(item.get("exercise"))
        sets = _pos_int(item.get("sets", 3), f"exercise {i} sets", 1, 20)
        reps = _pos_int(item.get("reps", 10), f"exercise {i} reps", 1, 200)
        rest = _pos_num(item.get("rest_seconds", 90), f"exercise {i} rest_seconds", 0, 900)
        weight = item.get("weight_kg")
        weight_kg = None if weight is None else _pos_num(weight, f"exercise {i} weight_kg", 0, 500)
        steps.append(create_strength_set(ex["category"], order, sets, reps, rest, exercise_name=ex["exercise"], weight_kg=weight_kg))
        order += 3
        load = f" @ {weight_kg:g} kg" if weight_kg is not None else ""
        lines.append(f"{i}. {ex['name']} — {sets} × {reps}{load}, rest {_fmt_secs(rest)}")
    workout = StrengthWorkout(
        workoutName=body["name"],
        description=body.get("description") or None,
        estimatedDurationInSecs=0,
        workoutSegments=[
            WorkoutSegment(
                segmentOrder=1,
                sportType={"sportTypeId": SportType.STRENGTH_TRAINING, "sportTypeKey": "strength_training"},
                workoutSteps=steps,
            )
        ],
    )
    return workout, lines


class _Order:
    def __init__(self) -> None:
        self.n = 0

    def next(self) -> int:
        self.n += 1
        if self.n > MAX_STEPS:
            raise BridgeError(400, "bad_request", f"workout has more than {MAX_STEPS} steps")
        return self.n


def _pace_mps(value: Any, field: str) -> float:
    m = PACE_RE.match(value) if isinstance(value, str) else None
    if not m:
        raise BridgeError(400, "bad_request", f'{field} must be a pace like "5:15" (min:sec per km)')
    secs = int(m.group(1)) * 60 + int(m.group(2))
    if not 120 <= secs <= 1200:
        raise BridgeError(400, "bad_request", f"{field} must be between 2:00 and 20:00 per km")
    return 1000 / secs


def _run_step(step: Any, order: _Order, depth: int, lines: list[str], indent: str) -> Any:
    if not isinstance(step, dict):
        raise BridgeError(400, "bad_request", "each step must be an object")
    kind = step.get("type")
    if kind == "repeat":
        if depth >= 1:
            raise BridgeError(400, "bad_request", "repeats can't be nested inside repeats")
        times = _pos_int(step.get("times"), "repeat times", 2, 50)
        inner = step.get("steps")
        if not isinstance(inner, list) or not inner:
            raise BridgeError(400, "bad_request", "a repeat needs a non-empty steps list")
        group_order = order.next()
        lines.append(f"{indent}Repeat {times}×:")
        children = [_run_step(s, order, depth + 1, lines, indent + "   ") for s in inner]
        return create_repeat_group(times, children, group_order)
    if kind not in RUN_STEP_TYPES:
        raise BridgeError(400, "bad_request", f"step type must be one of: {', '.join([*RUN_STEP_TYPES, 'repeat'])}")

    type_id, type_key, display = RUN_STEP_TYPES[kind]
    dist, dur = step.get("distance_m"), step.get("duration_s")
    if (dist is None) == (dur is None):
        raise BridgeError(400, "bad_request", f"{kind} step needs exactly one of duration_s or distance_m")
    if dist is not None:
        value = _pos_num(dist, f"{kind} distance_m", 50, 100_000)
        end = {"conditionTypeId": ConditionType.DISTANCE, "conditionTypeKey": "distance", "displayOrder": 3, "displayable": True}
        length = f"{value / 1000:g} km" if value >= 1000 else f"{value:g} m"
    else:
        value = _pos_num(dur, f"{kind} duration_s", 10, 6 * 3600)
        end = {"conditionTypeId": ConditionType.TIME, "conditionTypeKey": "time", "displayOrder": 2, "displayable": True}
        length = _fmt_secs(value)

    target: dict[str, Any] = {"targetType": NO_TARGET}
    label = ""
    pace, zone = step.get("pace"), step.get("hr_zone")
    if pace is not None and zone is not None:
        raise BridgeError(400, "bad_request", f"{kind} step: use pace or hr_zone, not both")
    if pace is not None:
        if not isinstance(pace, dict):
            raise BridgeError(400, "bad_request", 'pace must be {"fast": "4:50", "slow": "5:10"}')
        fast = _pace_mps(pace.get("fast"), "pace.fast")
        slow = _pace_mps(pace.get("slow"), "pace.slow")
        if fast < slow:
            raise BridgeError(400, "bad_request", "pace.fast must be quicker than (or equal to) pace.slow")
        target = {
            "targetType": {"workoutTargetTypeId": TargetType.PACE_ZONE, "workoutTargetTypeKey": "pace.zone", "displayOrder": 1},
            "targetValueOne": slow,
            "targetValueTwo": fast,
        }
        label = f" @ {pace['fast']}–{pace['slow']} /km"
    elif zone is not None:
        z = _pos_int(zone, "hr_zone", 1, 5)
        target = {
            "targetType": {"workoutTargetTypeId": TargetType.HEART_RATE_ZONE, "workoutTargetTypeKey": "heart.rate.zone", "displayOrder": 1},
            "zoneNumber": z,
        }
        label = f" in HR zone {z}"

    lines.append(f"{indent}{kind.capitalize()} {length}{label}")
    return ExecutableStep(
        stepOrder=order.next(),
        stepType={"stepTypeId": type_id, "stepTypeKey": type_key, "displayOrder": display},
        endCondition=end,
        endConditionValue=value,
        **target,
    )


def _build_run(body: dict[str, Any]) -> tuple[RunningWorkout, list[str]]:
    steps = body.get("steps")
    if not isinstance(steps, list) or not steps:
        raise BridgeError(400, "bad_request", "steps must be a non-empty list")
    order = _Order()
    lines: list[str] = []
    built = [_run_step(s, order, 0, lines, "") for s in steps]
    workout = RunningWorkout(
        workoutName=body["name"],
        description=body.get("description") or None,
        estimatedDurationInSecs=0,
        workoutSegments=[
            WorkoutSegment(
                segmentOrder=1,
                sportType={"sportTypeId": SportType.RUNNING, "sportTypeKey": "running"},
                workoutSteps=built,
            )
        ],
    )
    return workout, lines


def h_workouts_create(body: dict[str, Any]) -> dict[str, Any]:
    kind = body.get("kind")
    name = body.get("name")
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 80:
        raise BridgeError(400, "bad_request", "name is required (max 80 characters)")
    body = {**body, "name": name.strip()}
    if body.get("description") is not None and (not isinstance(body["description"], str) or len(body["description"]) > 500):
        raise BridgeError(400, "bad_request", "description must be text, max 500 characters")
    schedule = _date(body["schedule_date"], "schedule_date") if body.get("schedule_date") else None
    send = bool(body.get("send_to_watch"))

    try:
        if kind == "strength":
            workout, lines = _build_strength(body)
        elif kind == "run":
            workout, lines = _build_run(body)
        else:
            raise BridgeError(400, "bad_request", 'kind must be "strength" or "run"')
    except ValueError as exc:  # pydantic validation
        raise BridgeError(400, "bad_request", f"invalid workout: {str(exc)[:300]}") from exc

    preview = {"kind": kind, "name": body["name"], "steps": lines, "schedule_date": schedule, "send_to_watch": send}
    if body.get("dry_run", True):
        return {"status": "preview", "preview": preview}

    api = require_active()
    with _api_lock:
        created = api.upload_workout(workout.to_dict()) or {}
        workout_id = created.get("workoutId")
        if not workout_id:
            raise BridgeError(502, "garmin_unavailable", "Garmin accepted the request but returned no workout id")
        result: dict[str, Any] = {"status": "created", "workout_id": workout_id, "preview": preview}
        # Follow-on steps report their own failure without hiding the created workout.
        if schedule:
            try:
                sched = api.schedule_workout(workout_id, schedule) or {}
                result["scheduled_workout_id"] = sched.get("workoutScheduleId") or sched.get("id")
                result["scheduled"] = True
            except Exception as exc:  # noqa: BLE001
                result["schedule_error"] = translate(exc).message
        if send:
            try:
                api.push_workout_to_device(workout_id)
                result["sent_to_watch"] = True
            except Exception as exc:  # noqa: BLE001
                result["send_error"] = translate(exc).message
    return result


def h_workouts_list(body: dict[str, Any]) -> dict[str, Any]:
    api = require_active()
    months = body.get("months")
    if not isinstance(months, list) or not months:
        raise BridgeError(400, "bad_request", "months must be a list of [year, month]")
    with _api_lock:
        library = api.get_workouts(0, 30) or []
        scheduled: list[dict[str, Any]] = []
        for pair in months[:3]:
            if not (isinstance(pair, list) and len(pair) == 2):
                continue
            year, month = _pos_int(pair[0], "year", 2000, 2100), _pos_int(pair[1], "month", 1, 12)
            items = g(api.get_scheduled_workouts(year, month), "calendarItems") or []
            for it in items:
                if isinstance(it, dict) and it.get("itemType") == "workout":
                    scheduled.append({
                        "scheduled_workout_id": it.get("id"),
                        "workout_id": it.get("workoutId"),
                        "date": it.get("date"),
                        "name": it.get("title"),
                        "sport": it.get("sportTypeKey"),
                    })
    lib = [
        {
            "workout_id": w.get("workoutId"),
            "name": w.get("workoutName"),
            "sport": g(w, "sportType", "sportTypeKey"),
            "updated": w.get("updatedDate") or w.get("createdDate"),
        }
        for w in library
        if isinstance(w, dict)
    ]
    return {"library": lib, "scheduled": sorted(scheduled, key=lambda s: str(s.get("date") or ""))}


def _workout_name(api: Garmin, workout_id: int) -> str:
    try:
        return str((api.get_workout_by_id(workout_id) or {}).get("workoutName") or f"workout {workout_id}")
    except Exception as exc:  # noqa: BLE001
        err = translate(exc)
        if err.status in (401, 429):
            raise err from exc
        raise BridgeError(404, "not_found", f"No workout {workout_id} in your Garmin library") from exc


def h_workouts_schedule(body: dict[str, Any]) -> dict[str, Any]:
    workout_id = _pos_int(body.get("workout_id"), "workout_id")
    date = _date(body.get("date"), "date")
    send = bool(body.get("send_to_watch"))
    api = require_active()
    with _api_lock:
        name = _workout_name(api, workout_id)
        preview = {"name": name, "workout_id": workout_id, "date": date, "send_to_watch": send}
        if body.get("dry_run", True):
            return {"status": "preview", "preview": preview}
        sched = api.schedule_workout(workout_id, date) or {}
        result: dict[str, Any] = {"status": "scheduled", "preview": preview, "scheduled_workout_id": sched.get("workoutScheduleId") or sched.get("id")}
        if send:
            try:
                api.push_workout_to_device(workout_id)
                result["sent_to_watch"] = True
            except Exception as exc:  # noqa: BLE001
                result["send_error"] = translate(exc).message
    return result


def h_workouts_unschedule(body: dict[str, Any]) -> dict[str, Any]:
    sid = _pos_int(body.get("scheduled_workout_id"), "scheduled_workout_id")
    api = require_active()
    with _api_lock:
        try:
            item = api.get_scheduled_workout_by_id(sid) or {}
        except Exception as exc:  # noqa: BLE001
            err = translate(exc)
            if err.status in (401, 429):
                raise err from exc
            raise BridgeError(404, "not_found", f"No scheduled workout {sid}") from exc
        preview = {
            "scheduled_workout_id": sid,
            "date": item.get("calendarDate") or item.get("date"),
            "name": g(item, "workout", "workoutName") or item.get("title"),
        }
        if body.get("dry_run", True):
            return {"status": "preview", "preview": preview}
        api.unschedule_workout(sid)
    return {"status": "unscheduled", "preview": preview}


def h_workouts_delete(body: dict[str, Any]) -> dict[str, Any]:
    workout_id = _pos_int(body.get("workout_id"), "workout_id")
    api = require_active()
    with _api_lock:
        name = _workout_name(api, workout_id)
        preview = {"workout_id": workout_id, "name": name}
        if body.get("dry_run", True):
            return {"status": "preview", "preview": preview}
        api.delete_workout(workout_id)
    return {"status": "deleted", "preview": preview}


# ------------------------------------------------------------- weigh-ins ---

def _weigh_ins(api: Garmin, start: str, end: str) -> list[dict[str, Any]]:
    data = api.get_weigh_ins(start, end) or {}
    out = []
    for day in data.get("dailyWeightSummaries") or []:
        for m in (day or {}).get("allWeightMetrics") or []:
            if not isinstance(m, dict):
                continue
            grams = num(m.get("weight"))
            out.append({
                "weight_pk": m.get("samplePk"),
                "date": m.get("calendarDate") or day.get("summaryDate"),
                "time_local": m.get("date"),
                "weight_kg": round(grams / 1000, 2) if grams else None,
                "bmi": num(m.get("bmi")),
                "body_fat_pct": num(m.get("bodyFat")),
                "muscle_mass_kg": round(num(m.get("muscleMass")) / 1000, 2) if num(m.get("muscleMass")) else None,
                "source": m.get("sourceType"),
            })
    return sorted(out, key=lambda w: (str(w["date"]), str(w["time_local"])), reverse=True)


def h_weight_list(body: dict[str, Any]) -> dict[str, Any]:
    start, end = _date(body.get("start"), "start"), _date(body.get("end"), "end")
    api = require_active()
    with _api_lock:
        return {"weigh_ins": _weigh_ins(api, start, end)}


def h_weight_add(body: dict[str, Any]) -> dict[str, Any]:
    weight = _pos_num(body.get("weight_kg"), "weight_kg", 25, 300)
    date = _date(body.get("date"), "date")
    tm = body.get("time") or "07:00"
    if not isinstance(tm, str) or not re.match(r"^([01]\d|2[0-3]):[0-5]\d$", tm):
        raise BridgeError(400, "bad_request", "time must be HH:MM (24-hour)")
    stamp = f"{date}T{tm}:00"
    preview = {"weight_kg": round(weight, 2), "date": date, "time": tm, "timezone": os.environ.get("TZ", "system")}
    if body.get("dry_run", True):
        return {"status": "preview", "preview": preview}
    api = require_active()
    with _api_lock:
        # Naive local timestamp: the bridge runs with TZ set to the owner's zone,
        # so the library derives the correct GMT time from it.
        api.add_weigh_in(round(weight, 2), unitKey="kg", timestamp=stamp)
    return {"status": "logged", "preview": preview}


def h_weight_delete(body: dict[str, Any]) -> dict[str, Any]:
    pk = _pos_int(body.get("weight_pk"), "weight_pk")
    date = _date(body.get("date"), "date")
    api = require_active()
    with _api_lock:
        match = next((w for w in _weigh_ins(api, date, date) if w.get("weight_pk") == pk), None)
        if match is None:
            raise BridgeError(404, "not_found", f"No weigh-in {pk} on {date}")
        if body.get("dry_run", True):
            return {"status": "preview", "preview": match}
        api.delete_weigh_in(str(pk), date)
    return {"status": "deleted", "preview": match}


ROUTES = {
    "/status": h_status,
    "/session/load": h_load,
    "/login": h_login,
    "/login/mfa": h_login_mfa,
    "/daily": h_daily,
    "/activities": h_activities,
    "/workouts/list": h_workouts_list,
    "/workouts/create": h_workouts_create,
    "/workouts/schedule": h_workouts_schedule,
    "/workouts/unschedule": h_workouts_unschedule,
    "/workouts/delete": h_workouts_delete,
    "/weight/list": h_weight_list,
    "/weight/add": h_weight_add,
    "/weight/delete": h_weight_delete,
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
