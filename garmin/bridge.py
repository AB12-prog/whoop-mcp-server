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

import calendar
import hmac
import json
import logging
import os
import re
import secrets
import sys
import threading
import time
import datetime as dt
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
    BaseWorkout,
    ConditionType,
    ExecutableStep,
    SportType,
    StepType,
    StrengthWorkout,
    TargetType,
    WorkoutSegment,
    create_repeat_group,
    create_strength_rest_step,
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


def _load_balance_pick(ts: Any) -> dict[str, Any] | None:
    devices = g(ts, "mostRecentTrainingLoadBalance", "metricsTrainingLoadBalanceDTOMap")
    if not isinstance(devices, dict) or not devices:
        return None
    values = [v for v in devices.values() if isinstance(v, dict)]
    primary = [v for v in values if v.get("primaryTrainingDevice")]
    return (primary or values or [None])[0]


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def normalise_daily(day: str, raw: dict[str, Any]) -> dict[str, Any]:
    as_dict = _as_dict
    s = as_dict(raw.get("summary"))
    sleep_top = as_dict(raw.get("sleep"))
    d = as_dict(sleep_top.get("dailySleepDTO"))
    h = as_dict(g(raw.get("hrv"), "hrvSummary"))
    r = as_dict(_readiness_pick(raw.get("readiness")))
    tsd = as_dict(_training_status_pick(raw.get("training_status")))
    lb = as_dict(_load_balance_pick(raw.get("training_status")))
    vo2 = as_dict(g(raw.get("training_status"), "mostRecentVO2Max", "generic"))
    mm = raw.get("max_metrics")
    mm_generic = as_dict(g(mm, 0, "generic") if isinstance(mm, list) else g(mm, "generic"))
    fa = as_dict(raw.get("fitness_age"))
    hy = as_dict(raw.get("hydration"))
    fl = as_dict(raw.get("food_log"))
    fl_total = as_dict(fl.get("dailyNutritionContent"))
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
        "vo2max": num(vo2.get("vo2MaxPreciseValue")) or num(vo2.get("vo2MaxValue"))
        or num(mm_generic.get("vo2MaxPreciseValue")) or num(mm_generic.get("vo2MaxValue")),
        # --- added: daily summary detail
        "step_goal": num(s.get("dailyStepGoal")),
        "floors_up": num(s.get("floorsAscended")),
        "floors_down": num(s.get("floorsDescended")),
        "bmr_kcal": num(s.get("bmrKilocalories")),
        "active_s": num(s.get("activeSeconds")),
        "highly_active_s": num(s.get("highlyActiveSeconds")),
        "sedentary_s": num(s.get("sedentarySeconds")),
        "stress_rest_s": num(s.get("restStressDuration")),
        "stress_low_s": num(s.get("lowStressDuration")),
        "stress_medium_s": num(s.get("mediumStressDuration")),
        "stress_high_s": num(s.get("highStressDuration")),
        "stress_qualifier": s.get("stressQualifier"),
        # --- added: sleep detail
        "nap_s": num(d.get("napTimeSeconds")),
        "sleep_start_local": num(d.get("sleepStartTimestampLocal")),
        "sleep_end_local": num(d.get("sleepEndTimestampLocal")),
        "sleep_hrv_avg": num(d.get("avgSleepHRV")) or num(sleep_top.get("avgOvernightHrv")),
        "sleep_avg_hr": num(d.get("avgHeartRate")),
        "sleep_resp_low": num(d.get("lowestRespirationValue")),
        "sleep_resp_high": num(d.get("highestRespirationValue")),
        "sleep_awake_count": num(d.get("awakeCount")),
        "sleep_restless_moments": num(sleep_top.get("restlessMomentsCount")),
        "sleep_bb_change": num(sleep_top.get("bodyBatteryChange")),
        "sleep_need_min": num(g(d, "sleepNeed", "actual")),
        "sleep_feedback": d.get("sleepScoreFeedback"),
        "sleep_deep_pct": num(g(d, "sleepScores", "deepPercentage", "value")),
        "sleep_light_pct": num(g(d, "sleepScores", "lightPercentage", "value")),
        "sleep_rem_pct": num(g(d, "sleepScores", "remPercentage", "value")),
        "sleep_q_duration": g(d, "sleepScores", "totalDuration", "qualifierKey"),
        "sleep_q_stress": g(d, "sleepScores", "stress", "qualifierKey"),
        "sleep_q_restlessness": g(d, "sleepScores", "restlessness", "qualifierKey"),
        # --- added: HRV / readiness factors
        "hrv_feedback": h.get("feedbackPhrase"),
        "readiness_sleep_score": num(r.get("sleepScore")),
        "readiness_sleep_pct": num(r.get("sleepScoreFactorPercent")),
        "readiness_sleep_history_pct": num(r.get("sleepHistoryFactorPercent")),
        "readiness_recovery_pct": num(r.get("recoveryTimeFactorPercent")),
        "readiness_acwr_pct": num(r.get("acwrFactorPercent")),
        "readiness_hrv_pct": num(r.get("hrvFactorPercent")),
        "readiness_stress_pct": num(r.get("stressHistoryFactorPercent")),
        "readiness_feedback_long": r.get("feedbackLong"),
        # --- added: training load balance (4-week)
        "load_aerobic_low": num(lb.get("monthlyLoadAerobicLow")),
        "load_aerobic_high": num(lb.get("monthlyLoadAerobicHigh")),
        "load_anaerobic": num(lb.get("monthlyLoadAnaerobic")),
        "load_balance_feedback": lb.get("trainingBalanceFeedbackPhrase"),
        # --- added: fitness age, hydration
        "fitness_age": num(fa.get("fitnessAge")),
        "fitness_age_achievable": num(fa.get("achievableFitnessAge")),
        "hydration_ml": num(hy.get("valueInML")),
        "hydration_goal_ml": num(hy.get("goalInML")),
        "sweat_loss_ml": num(hy.get("sweatLossInML")),
        # --- added: Garmin food log (Connect+ nutrition)
        "food_kcal": num(fl_total.get("calories")),
        "food_protein_g": num(fl_total.get("protein")),
        "food_carbs_g": num(fl_total.get("carbs")),
        "food_fat_g": num(fl_total.get("fat")),
        "food_fiber_g": num(fl_total.get("fiber")),
        "food_items": sum(len(m.get("loggedFoods") or []) for m in fl.get("mealDetails") or [] if isinstance(m, dict)) if fl else None,
    }


# Per-day sources, in fetch order. Keep the names in step with DAILY_SOURCES in
# src/garmin.ts. Each is one Garmin call.
def _daily_calls(api: Garmin) -> dict[str, Any]:
    return {
        "summary": api.get_user_summary,
        "sleep": api.get_sleep_data,
        "hrv": api.get_hrv_data,
        "readiness": api.get_training_readiness,
        "training_status": api.get_training_status,
        "heart_rates": api.get_heart_rates,
        "stress": api.get_stress_data,
        "body_battery_events": api.get_body_battery_events,
        "respiration": api.get_respiration_data,
        "spo2": api.get_spo2_data,
        "steps": api.get_steps_data,
        "max_metrics": api.get_max_metrics,
        "fitness_age": api.get_fitnessage_data,
        "hydration": api.get_hydration_data,
        "lifestyle": api.get_lifestyle_logging_data,
        "all_day_events": api.get_all_day_events,
        "food_log": lambda d: api.connectapi(f"/nutrition-service/food/logs/{d}"),
    }


# ------------------------------------------------------------- intraday ---

_GMT_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})")


def ts_ms(value: Any) -> int | None:
    """Epoch milliseconds (UTC) from Garmin's mix of ms numbers and GMT strings."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        v = int(value)
        if v > 10**11:
            return v
        if v > 10**9:
            return v * 1000
        return None
    if isinstance(value, str):
        m = _GMT_RE.match(value)
        if not m:
            return None
        y, mo, dd, hh, mi, ss = (int(x) for x in m.groups())
        return calendar.timegm((y, mo, dd, hh, mi, ss, 0, 0, 0)) * 1000
    return None


def _descriptor_index(descriptors: Any, wanted: str, default: int) -> int:
    """Find the array position of `wanted` in Garmin's *ValueDescriptor* lists."""
    if isinstance(descriptors, list):
        for d in descriptors:
            if not isinstance(d, dict):
                continue
            key = next((v for k, v in d.items() if k.lower().endswith("key")), None)
            idx = next((v for k, v in d.items() if k.lower().endswith("index")), None)
            if isinstance(key, str) and key.lower() == wanted.lower() and isinstance(idx, int):
                return idx
    return default


def _pairs(rows: Any, value_idx: int = 1, ts_idx: int = 0, min_value: float = 0) -> list[list[float]]:
    out: list[list[float]] = []
    if not isinstance(rows, list):
        return out
    for row in rows:
        if not isinstance(row, list) or len(row) <= max(ts_idx, value_idx):
            continue
        t, v = ts_ms(row[ts_idx]), num(row[value_idx])
        if t is None or v is None or v < min_value:
            continue  # Garmin uses -1/-2 for "not measured"
        out.append([t, v])
    return out


def extract_intraday(raw: dict[str, Any]) -> dict[str, list[list[float]]]:
    """Pull the time series out of the day's raw responses as [epoch_ms, value]."""
    out: dict[str, list[list[float]]] = {}

    out["hr"] = _pairs(g(raw, "heart_rates", "heartRateValues"), min_value=1)

    stress = _as_dict(raw.get("stress"))
    s_idx = _descriptor_index(stress.get("stressValueDescriptorsDTOList"), "stressLevel", 1)
    s_ts = _descriptor_index(stress.get("stressValueDescriptorsDTOList"), "timestamp", 0)
    out["stress"] = _pairs(stress.get("stressValuesArray"), s_idx, s_ts)
    bb_desc = stress.get("bodyBatteryValueDescriptorsDTOList") or stress.get("bodyBatteryValueDescriptorDTOList")
    bb_rows = stress.get("bodyBatteryValuesArray")
    bb_default = 2 if isinstance(bb_rows, list) and bb_rows and isinstance(bb_rows[0], list) and len(bb_rows[0]) >= 3 else 1
    out["body_battery"] = _pairs(bb_rows, _descriptor_index(bb_desc, "bodyBatteryLevel", bb_default), _descriptor_index(bb_desc, "timestamp", 0))

    resp = _as_dict(raw.get("respiration"))
    out["respiration"] = _pairs(resp.get("respirationValuesArray"), min_value=1)

    spo2 = _as_dict(raw.get("spo2"))
    out["spo2"] = _pairs(spo2.get("spO2SingleValues"), min_value=1)
    out["spo2_hourly"] = _pairs(spo2.get("spO2HourlyAverages"), min_value=1)

    steps: list[list[float]] = []
    for row in raw.get("steps") if isinstance(raw.get("steps"), list) else []:
        if isinstance(row, dict):
            t, v = ts_ms(row.get("startGMT")), num(row.get("steps"))
            if t is not None and v is not None:
                steps.append([t, v])
    out["steps"] = steps

    hrv: list[list[float]] = []
    for row in g(raw, "hrv", "hrvReadings") or []:
        if isinstance(row, dict):
            t, v = ts_ms(row.get("readingTimeGMT")), num(row.get("hrvValue"))
            if t is not None and v is not None and v > 0:
                hrv.append([t, v])
    out["hrv"] = hrv

    # Sleep stages as change points: 0 deep, 1 light, 2 REM, 3 awake.
    stages: list[list[float]] = []
    for row in g(raw, "sleep", "sleepLevels") or []:
        if isinstance(row, dict):
            t, v = ts_ms(row.get("startGMT")), num(row.get("activityLevel"))
            if t is not None and v is not None:
                stages.append([t, v])
    out["sleep_stage"] = stages

    return {k: v for k, v in out.items() if v}


def h_daily(body: dict[str, Any]) -> dict[str, Any]:
    day = body.get("date")
    if not isinstance(day, str) or not DATE_RE.match(day):
        raise BridgeError(400, "bad_request", "date (YYYY-MM-DD) required")
    api = require_active()
    calls = _daily_calls(api)
    wanted = body.get("sources")
    if isinstance(wanted, list) and wanted:
        calls = {k: v for k, v in calls.items() if k in wanted}
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
    return {
        "date": day,
        "normalised": normalise_daily(day, raw),
        "intraday": extract_intraday(raw),
        "raw": raw,
        "errors": errors,
    }


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
        **activity_extras(a),
    }


# (activity-list key, activity-detail summaryDTO key, column). Values are
# Garmin's units: speeds m/s, stride cm, ground contact ms, oscillation cm.
_ACTIVITY_EXTRA_FIELDS: list[tuple[str, str | None, str]] = [
    ("elapsedDuration", "elapsedDuration", "elapsed_s"),
    ("maxSpeed", "maxSpeed", "max_speed"),
    ("elevationLoss", "elevationLoss", "elevation_loss"),
    ("minElevation", "minElevation", "min_elevation"),
    ("maxElevation", "maxElevation", "max_elevation"),
    ("averageRunningCadenceInStepsPerMinute", "averageRunCadence", "avg_cadence"),
    ("maxRunningCadenceInStepsPerMinute", "maxRunCadence", "max_cadence"),
    ("avgStrideLength", "strideLength", "stride_cm"),
    ("avgGroundContactTime", "groundContactTime", "gct_ms"),
    ("avgVerticalOscillation", "verticalOscillation", "vert_osc_cm"),
    ("avgVerticalRatio", "verticalRatio", "vert_ratio"),
    ("avgPower", "averagePower", "avg_power"),
    ("maxPower", "maxPower", "max_power"),
    ("normPower", "normalizedPower", "norm_power"),
    ("avgGradeAdjustedSpeed", "avgGradeAdjustedSpeed", "gap_speed"),
    ("avgRespirationRate", "avgRespirationRate", "avg_resp"),
    ("minHR", "minHR", "min_hr"),
    ("vO2MaxValue", None, "vo2max"),
    ("trainingEffectLabel", "trainingEffectLabel", "te_label"),
    ("aerobicTrainingEffectMessage", "aerobicTrainingEffectMessage", "aerobic_te_msg"),
    ("anaerobicTrainingEffectMessage", "anaerobicTrainingEffectMessage", "anaerobic_te_msg"),
    ("minTemperature", "minTemperature", "min_temp_c"),
    ("maxTemperature", "maxTemperature", "max_temp_c"),
    ("steps", "steps", "steps"),
    ("differenceBodyBattery", "differenceBodyBattery", "bb_change"),
    ("moderateIntensityMinutes", "moderateIntensityMinutes", "intensity_moderate_min"),
    ("vigorousIntensityMinutes", "vigorousIntensityMinutes", "intensity_vigorous_min"),
    ("waterEstimated", "waterEstimated", "sweat_ml"),
    ("totalSets", None, "total_sets"),
    ("activeSets", None, "active_sets"),
    ("totalReps", None, "total_reps"),
    ("totalVolume", None, "total_volume"),
    ("lapCount", None, "lap_count"),
    ("locationName", None, "location"),
    ("description", None, "description"),
]
_TEXT_EXTRAS = {"te_label", "aerobic_te_msg", "anaerobic_te_msg", "location", "description"}


def activity_extras(a: dict[str, Any], summary: dict[str, Any] | None = None) -> dict[str, Any]:
    summary = summary or {}
    out: dict[str, Any] = {}
    for list_key, summary_key, col in _ACTIVITY_EXTRA_FIELDS:
        value = a.get(list_key)
        if value is None and summary_key:
            value = summary.get(summary_key)
        if col in _TEXT_EXTRAS:
            out[col] = value if isinstance(value, str) and value else None
        else:
            out[col] = num(value)
    return out


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


# Detail time series: Garmin downsamples to at most this many points.
MAX_CHART = int(os.environ.get("GARMIN_MAX_CHART", "4000"))
MAX_POLY = int(os.environ.get("GARMIN_MAX_POLYLINE", "4000"))


def _norm_lap(i: int, lap: dict[str, Any]) -> dict[str, Any]:
    idx = lap.get("lapIndex")
    return {
        "lap_index": idx if isinstance(idx, int) else i + 1,
        "start_gmt": lap.get("startTimeGMT"),
        "duration_s": num(lap.get("duration")),
        "moving_s": num(lap.get("movingDuration")),
        "distance_m": num(lap.get("distance")),
        "avg_speed": num(lap.get("averageSpeed")),
        "gap_speed": num(lap.get("avgGradeAdjustedSpeed")),
        "max_speed": num(lap.get("maxSpeed")),
        "avg_hr": num(lap.get("averageHR")),
        "max_hr": num(lap.get("maxHR")),
        "avg_cadence": num(lap.get("averageRunCadence")),
        "max_cadence": num(lap.get("maxRunCadence")),
        "stride_cm": num(lap.get("strideLength")),
        "gct_ms": num(lap.get("groundContactTime")),
        "vert_osc_cm": num(lap.get("verticalOscillation")),
        "vert_ratio": num(lap.get("verticalRatio")),
        "avg_power": num(lap.get("averagePower")),
        "elevation_gain": num(lap.get("elevationGain")),
        "elevation_loss": num(lap.get("elevationLoss")),
        "kcal": num(lap.get("calories")),
        "intensity": lap.get("intensityType") if isinstance(lap.get("intensityType"), str) else None,
    }


def _norm_sets(raw: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for i, s in enumerate(g(raw, "exerciseSets") or []):
        if not isinstance(s, dict):
            continue
        exs = [e for e in s.get("exercises") or [] if isinstance(e, dict)]
        top = max(exs, key=lambda e: num(e.get("probability")) or 0) if exs else {}
        grams = num(s.get("weight"))
        out.append({
            "set_index": i + 1,
            "set_type": s.get("setType"),
            "category": top.get("category"),
            "exercise": top.get("name"),
            "reps": num(s.get("repetitionCount")),
            # Garmin reports set weight in grams.
            "weight_kg": round(grams / 1000, 2) if grams else None,
            "duration_s": num(s.get("duration")),
            "start_gmt": s.get("startTime"),
        })
    return out


def _norm_zones(raw: Any) -> list[dict[str, Any]]:
    out = []
    for z in raw if isinstance(raw, list) else []:
        if isinstance(z, dict) and z.get("zoneNumber") is not None:
            out.append({"zone": z.get("zoneNumber"), "secs": num(z.get("secsInZone")), "low": num(z.get("zoneLowBoundary"))})
    return out


def h_activity_detail(body: dict[str, Any]) -> dict[str, Any]:
    """Everything Garmin keeps for one activity: full summary, laps, typed
    splits, HR/power zones, weather, the recorded time series and (for strength)
    the exercise sets."""
    activity_id = _pos_int(body.get("activity_id"), "activity_id")
    type_key = str(body.get("type_key") or "")
    api = require_active()
    aid = str(activity_id)
    raw: dict[str, Any] = {}
    errors: dict[str, str] = {}

    def fetch(name: str, fn: Any, *args: Any, **kwargs: Any) -> None:
        if raw:
            time.sleep(CALL_GAP_S)
        try:
            raw[name] = fn(*args, **kwargs)
        except (GarminConnectAuthenticationError, GarminConnectTooManyRequestsError):
            raise
        except Exception as exc:  # noqa: BLE001
            raw[name] = None
            errors[name] = f"{type(exc).__name__}: {str(exc)[:200]}"

    with _api_lock:
        fetch("summary", api.get_activity, aid)
        summary = _as_dict(g(raw.get("summary"), "summaryDTO"))
        type_key = type_key or str(g(raw.get("summary"), "activityTypeDTO", "typeKey") or "")
        fetch("splits", api.get_activity_splits, aid)
        fetch("typed_splits", api.get_activity_typed_splits, aid)
        fetch("split_summaries", api.get_activity_split_summaries, aid)
        fetch("hr_zones", api.get_activity_hr_in_timezones, aid)
        if num(summary.get("averagePower")):
            fetch("power_zones", api.get_activity_power_in_timezones, aid)
        fetch("weather", api.get_activity_weather, aid)
        fetch("details", api.get_activity_details, aid, MAX_CHART, MAX_POLY)
        if body.get("has_sets") or any(k in type_key for k in ("strength", "hiit", "cardio", "fitness_equipment")):
            fetch("exercise_sets", api.get_activity_exercise_sets, activity_id)

    extras = activity_extras({}, summary)
    extras["location"] = extras.get("location") or g(raw.get("summary"), "locationName")
    laps = [_norm_lap(i, lap) for i, lap in enumerate(g(raw.get("splits"), "lapDTOs") or []) if isinstance(lap, dict)]
    return {
        "activity_id": activity_id,
        "extras": extras,
        "laps": laps,
        "sets": _norm_sets(raw.get("exercise_sets")),
        "zones": _norm_zones(raw.get("hr_zones")),
        "raw": raw,
        "errors": errors,
    }


def _days_before(day: str, n: int) -> str:
    return (dt.date.fromisoformat(day) - dt.timedelta(days=n)).isoformat()


def h_profile(body: dict[str, Any]) -> dict[str, Any]:
    """Account-level and long-range data that isn't tied to a single day."""
    today = _date(body.get("today"), "today")
    year_ago = _days_before(today, 365)
    two_years = _days_before(today, 730)
    api = require_active()
    calls: dict[str, Any] = {
        "user_settings": lambda: api.get_userprofile_settings(),
        "heart_rate_zones": lambda: api.get_heart_rate_zones(),
        "personal_records": lambda: api.get_personal_record(),
        "race_predictions": lambda: api.get_race_predictions(),
        "race_predictions_history": lambda: api.get_race_predictions(year_ago, today, "daily"),
        "lactate_threshold": lambda: api.get_lactate_threshold(latest=True),
        "lactate_threshold_history": lambda: api.get_lactate_threshold(latest=False, start_date=two_years, end_date=today),
        "endurance_score": lambda: api.get_endurance_score(year_ago, today),
        "hill_score": lambda: api.get_hill_score(year_ago, today),
        "running_tolerance": lambda: api.get_running_tolerance(year_ago, today, "weekly"),
        "body_composition": lambda: api.get_body_composition(two_years, today),
        "devices": lambda: api.get_devices(),
        "primary_device": lambda: api.get_primary_training_device(),
        "goals": lambda: api.get_goals("active"),
        "training_plans": lambda: api.get_training_plans(),
    }
    out: dict[str, Any] = {}
    errors: dict[str, str] = {}
    with _api_lock:
        for i, (name, fn) in enumerate(calls.items()):
            if i:
                time.sleep(CALL_GAP_S)
            try:
                out[name] = fn()
            except (GarminConnectAuthenticationError, GarminConnectTooManyRequestsError):
                raise
            except Exception as exc:  # noqa: BLE001
                out[name] = None
                errors[name] = f"{type(exc).__name__}: {str(exc)[:200]}"
    return {"snapshots": out, "errors": errors}


# ------------------------------------------------------------- workouts ---
#
# Every write takes "dry_run": when true the request is fully validated and
# built (exercise names resolved, steps assembled) and a human-readable preview
# is returned, but nothing is sent to Garmin. Node maps the tools' `confirm`
# flag onto this, so a write always has a preview step before it happens.

DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
PACE_RE = re.compile(r"^(\d{1,2}):([0-5]\d)$")
NO_TARGET = {"workoutTargetTypeId": TargetType.NO_TARGET, "workoutTargetTypeKey": "no.target", "displayOrder": 1}
STEP_TYPES = {
    "warmup": (StepType.WARMUP, "warmup", 1),
    "cooldown": (StepType.COOLDOWN, "cooldown", 2),
    "interval": (StepType.INTERVAL, "interval", 3),
    "recovery": (StepType.RECOVERY, "recovery", 4),
    "rest": (StepType.REST, "rest", 5),
    "other": (StepType.OTHER, "other", 7),
}
MAX_STEPS = 60

# Garmin reads a step's weightValue in the unit named by weightUnit (kg here).
# garminconnect 0.3.x multiplies kg by 1000 first ("grams"), which Garmin then
# shows as tonnes, so strength steps are built here instead of with
# create_strength_set(weight_kg=...).
WEIGHT_UNIT_KG = {"unitId": 8, "unitKey": "kilogram", "factor": 1000.0}

# Workout sport types (ids from /workout-service/workout/types):
# key -> (sportTypeId, sportTypeKey, displayOrder, label)
SPORTS: dict[str, tuple[int, str, int, str]] = {
    "running": (SportType.RUNNING, "running", 1, "Run"),
    "cycling": (SportType.CYCLING, "cycling", 2, "Bike"),
    "other": (SportType.OTHER, "other", 3, "Other"),
    "swimming": (SportType.SWIMMING, "swimming", 3, "Pool swim"),
    "strength_training": (SportType.STRENGTH_TRAINING, "strength_training", 5, "Strength"),
    "cardio_training": (SportType.CARDIO_TRAINING, "cardio_training", 6, "Cardio"),
    "yoga": (SportType.YOGA, "yoga", 7, "Yoga"),
    "pilates": (SportType.PILATES, "pilates", 8, "Pilates"),
    "hiit": (SportType.HIIT, "hiit", 9, "HIIT"),
    "mobility": (SportType.MOBILITY, "mobility", 11, "Mobility"),
    "walking": (17, "walking", 17, "Walk"),
    "hiking": (18, "hiking", 18, "Hike"),
}
# Everyday names. Machines without a workout type of their own (rower,
# elliptical, stair climber, ski erg) are Garmin "cardio" workouts.
SPORT_ALIASES = {
    "run": "running", "treadmill": "running", "trail_running": "running",
    "bike": "cycling", "ride": "cycling", "cycle": "cycling", "indoor_cycling": "cycling", "spin": "cycling", "virtual_ride": "cycling",
    "swim": "swimming", "pool_swim": "swimming", "lap_swimming": "swimming",
    "strength": "strength_training",
    "cardio": "cardio_training", "rowing": "cardio_training", "indoor_rowing": "cardio_training", "rower": "cardio_training",
    "erg": "cardio_training", "elliptical": "cardio_training", "stair": "cardio_training", "stairs": "cardio_training",
    "stair_climber": "cardio_training", "ski_erg": "cardio_training",
    "walk": "walking", "hike": "hiking",
}
EXERCISE_SPORTS = {"cardio_training", "hiit", "yoga", "pilates", "mobility", "other", "strength_training"}
PACE_SPORTS = {"running", "walking", "hiking"}
TARGET_KEYS = ("hr_zone", "hr_bpm", "pace", "speed_kmh", "power_zone", "power_w", "cadence")
END_KEYS = ("duration_s", "distance_m", "reps", "calories", "lap_button")


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


INTERVAL_STEP = {"stepTypeId": StepType.INTERVAL, "stepTypeKey": "interval", "displayOrder": 3}
COND_REPS = {"conditionTypeId": ConditionType.REPS, "conditionTypeKey": "reps", "displayOrder": 10, "displayable": True}
COND_TIME = {"conditionTypeId": ConditionType.TIME, "conditionTypeKey": "time", "displayOrder": 2, "displayable": True}
COND_DISTANCE = {"conditionTypeId": ConditionType.DISTANCE, "conditionTypeKey": "distance", "displayOrder": 3, "displayable": True}
COND_CALORIES = {"conditionTypeId": ConditionType.CALORIES, "conditionTypeKey": "calories", "displayOrder": 4, "displayable": True}
COND_LAP = {"conditionTypeId": ConditionType.LAP_BUTTON, "conditionTypeKey": "lap.button", "displayOrder": 1, "displayable": True}


def _weight_fields(weight_kg: float | None) -> dict[str, Any]:
    if weight_kg is None:
        return {}
    return {"weightValue": round(float(weight_kg), 2), "weightUnit": dict(WEIGHT_UNIT_KG)}


def _strength_block(ex: dict[str, str], order: int, sets: int, reps: int | None, duration: float | None,
                    rest: float, weight_kg: float | None) -> Any:
    """One "N sets" block: a repeat group of [exercise, rest]. Takes stepOrder
    order..order+2, like garminconnect's create_strength_set."""
    end, value = (COND_REPS, float(reps)) if duration is None else (COND_TIME, float(duration))
    exercise = ExecutableStep(
        stepOrder=order + 1,
        stepType=INTERVAL_STEP,
        endCondition=end,
        endConditionValue=value,
        targetType=NO_TARGET,
        category=ex["category"],
        exerciseName=ex["exercise"],
        **_weight_fields(weight_kg),
    )
    return create_repeat_group(sets, [exercise, create_strength_rest_step(rest, order + 2)], order)


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
        if item.get("duration_s") is not None and item.get("reps") is not None:
            raise BridgeError(400, "bad_request", f"exercise {i}: use reps or duration_s, not both")
        duration = None if item.get("duration_s") is None else _pos_num(item["duration_s"], f"exercise {i} duration_s", 5, 3600)
        reps = None if duration is not None else _pos_int(item.get("reps", 10), f"exercise {i} reps", 1, 200)
        rest = _pos_num(item.get("rest_seconds", 90), f"exercise {i} rest_seconds", 0, 900)
        weight = item.get("weight_kg")
        weight_kg = None if weight is None else _pos_num(weight, f"exercise {i} weight_kg", 0, 500)
        steps.append(_strength_block(ex, order, sets, reps, duration, rest, weight_kg))
        order += 3
        load = f" @ {weight_kg:g} kg" if weight_kg is not None else ""
        amount = f"{reps}" if duration is None else _fmt_secs(duration)
        lines.append(f"{i}. {ex['name']} — {sets} × {amount}{load}, rest {_fmt_secs(rest)}")
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


def _resolve_sport(value: Any) -> str:
    key = re.sub(r"[\s\-]+", "_", str(value or "").strip().lower())
    key = SPORT_ALIASES.get(key, key)
    if key not in SPORTS:
        names = ", ".join(sorted(SPORTS))
        raise BridgeError(400, "bad_request", f"sport must be one of: {names} (aliases such as bike, rowing, elliptical, walk and hike also work)")
    return key


def _target(type_id: int, key: str) -> dict[str, Any]:
    return {"workoutTargetTypeId": type_id, "workoutTargetTypeKey": key, "displayOrder": 1}


def _low_high(value: Any, field: str, lo: float, hi: float) -> tuple[float, float]:
    if not isinstance(value, dict):
        raise BridgeError(400, "bad_request", f'{field} must be {{"low": …, "high": …}}')
    a = _pos_num(value.get("low"), f"{field}.low", lo, hi)
    b = _pos_num(value.get("high"), f"{field}.high", lo, hi)
    if a > b:
        raise BridgeError(400, "bad_request", f"{field}.low must be at or below {field}.high")
    return a, b


def _parse_target(step: dict[str, Any], kind: str, sport: str) -> tuple[dict[str, Any], str]:
    given = [k for k in TARGET_KEYS if step.get(k) is not None]
    if len(given) > 1:
        raise BridgeError(400, "bad_request", f"{kind} step: use one target per step (got {', '.join(given)})")
    if not given:
        return {"targetType": NO_TARGET}, ""
    key, value = given[0], step[given[0]]
    if key == "hr_zone":
        z = _pos_int(value, "hr_zone", 1, 5)
        return {"targetType": _target(TargetType.HEART_RATE_ZONE, "heart.rate.zone"), "zoneNumber": z}, f" in HR zone {z}"
    if key == "hr_bpm":
        a, b = _low_high(value, "hr_bpm", 40, 230)
        return {"targetType": _target(TargetType.HEART_RATE_ZONE, "heart.rate.zone"), "targetValueOne": a, "targetValueTwo": b}, f" at {a:g}–{b:g} bpm"
    if key == "pace":
        if sport not in PACE_SPORTS:
            raise BridgeError(400, "bad_request", f"pace targets are for running, walking and hiking; on a {sport} workout use speed_kmh, power or heart rate")
        if not isinstance(value, dict):
            raise BridgeError(400, "bad_request", 'pace must be {"fast": "4:50", "slow": "5:10"}')
        fast = _pace_mps(value.get("fast"), "pace.fast")
        slow = _pace_mps(value.get("slow"), "pace.slow")
        if fast < slow:
            raise BridgeError(400, "bad_request", "pace.fast must be quicker than (or equal to) pace.slow")
        return ({"targetType": _target(TargetType.PACE_ZONE, "pace.zone"), "targetValueOne": slow, "targetValueTwo": fast},
                f" @ {value['fast']}–{value['slow']} /km")
    if key == "speed_kmh":
        a, b = _low_high(value, "speed_kmh", 1, 100)
        return {"targetType": _target(TargetType.SPEED_ZONE, "speed.zone"), "targetValueOne": a / 3.6, "targetValueTwo": b / 3.6}, f" at {a:g}–{b:g} km/h"
    if key == "power_zone":
        z = _pos_int(value, "power_zone", 1, 7)
        return {"targetType": _target(TargetType.POWER_ZONE, "power.zone"), "zoneNumber": z}, f" in power zone {z}"
    if key == "power_w":
        a, b = _low_high(value, "power_w", 20, 2500)
        return {"targetType": _target(TargetType.POWER_ZONE, "power.zone"), "targetValueOne": a, "targetValueTwo": b}, f" at {a:g}–{b:g} W"
    a, b = _low_high(value, "cadence", 10, 250)
    unit = "spm" if sport in PACE_SPORTS else "rpm"
    return {"targetType": _target(TargetType.CADENCE, "cadence"), "targetValueOne": a, "targetValueTwo": b}, f" at {a:g}–{b:g} {unit}"


def _parse_end(step: dict[str, Any], kind: str, has_exercise: bool) -> tuple[dict[str, Any], float | None, str]:
    given = [k for k in END_KEYS if step.get(k) is not None and step.get(k) is not False]
    if len(given) != 1:
        raise BridgeError(400, "bad_request", f"{kind} step needs exactly one of duration_s, distance_m, reps, calories or lap_button: true")
    key = given[0]
    if key == "duration_s":
        value = _pos_num(step[key], f"{kind} duration_s", 5, 6 * 3600)
        return COND_TIME, value, _fmt_secs(value)
    if key == "distance_m":
        value = _pos_num(step[key], f"{kind} distance_m", 10, 300_000)
        return COND_DISTANCE, value, (f"{value / 1000:g} km" if value >= 1000 else f"{value:g} m")
    if key == "reps":
        if not has_exercise:
            raise BridgeError(400, "bad_request", f"{kind} step: reps needs an exercise")
        value = float(_pos_int(step[key], f"{kind} reps", 1, 500))
        return COND_REPS, value, f"{int(value)} reps"
    if key == "calories":
        value = _pos_num(step[key], f"{kind} calories", 5, 5000)
        return COND_CALORIES, value, f"{value:g} kcal"
    if step[key] is not True:
        raise BridgeError(400, "bad_request", f"{kind} step: lap_button must be true")
    return COND_LAP, None, "until lap press"


def _step(step: Any, order: _Order, depth: int, lines: list[str], indent: str, sport: str) -> Any:
    if not isinstance(step, dict):
        raise BridgeError(400, "bad_request", "each step must be an object")
    kind = step.get("type")
    if kind == "repeat":
        if depth >= 1:
            raise BridgeError(400, "bad_request", "repeats can't be nested inside repeats")
        times = _pos_int(step.get("times"), "repeat times", 2, 99)
        inner = step.get("steps")
        if not isinstance(inner, list) or not inner:
            raise BridgeError(400, "bad_request", "a repeat needs a non-empty steps list")
        group_order = order.next()
        lines.append(f"{indent}Repeat {times}×:")
        children = [_step(s, order, depth + 1, lines, indent + "   ", sport) for s in inner]
        return create_repeat_group(times, children, group_order)
    if kind not in STEP_TYPES:
        raise BridgeError(400, "bad_request", f"step type must be one of: {', '.join([*STEP_TYPES, 'repeat'])}")

    type_id, type_key, display = STEP_TYPES[kind]
    extra: dict[str, Any] = {}
    ex_label = ""
    if step.get("exercise") is not None:
        if sport not in EXERCISE_SPORTS:
            raise BridgeError(400, "bad_request", f"exercises go on cardio, HIIT, yoga, pilates, mobility, strength or other workouts, not {sport}")
        ex = _resolve_exercise(step["exercise"])
        extra.update(category=ex["category"], exerciseName=ex["exercise"])
        ex_label = f" {ex['name']}"
    end, value, length = _parse_end(step, kind, bool(ex_label))
    load = ""
    if step.get("weight_kg") is not None:
        if not ex_label:
            raise BridgeError(400, "bad_request", f"{kind} step: weight_kg needs an exercise")
        w = _pos_num(step["weight_kg"], f"{kind} weight_kg", 0, 500)
        extra.update(_weight_fields(w))
        load = f" @ {w:g} kg"
    target, tlabel = _parse_target(step, kind, sport)
    notes = step.get("notes")
    if notes is not None:
        if not isinstance(notes, str) or len(notes) > 200:
            raise BridgeError(400, "bad_request", f"{kind} step: notes must be text, max 200 characters")
        notes = notes.strip()
        if notes:
            extra["description"] = notes

    lines.append(f"{indent}{kind.capitalize()}{ex_label} {length}{load}{tlabel}" + (f" — {notes}" if notes else ""))
    fields: dict[str, Any] = {
        "stepOrder": order.next(),
        "stepType": {"stepTypeId": type_id, "stepTypeKey": type_key, "displayOrder": display},
        "endCondition": end,
        **target,
        **extra,
    }
    if value is not None:
        fields["endConditionValue"] = value
    return ExecutableStep(**fields)


def _sport_type(sport: str) -> dict[str, Any]:
    sid, key, disp, _ = SPORTS[sport]
    return {"sportTypeId": sid, "sportTypeKey": key, "displayOrder": disp}


def _build_sport(body: dict[str, Any], sport: str) -> tuple[BaseWorkout, list[str]]:
    """Any-sport structured workout: timed/distance/rep/calorie/lap steps,
    repeats, and HR, pace, speed, power or cadence targets."""
    steps = body.get("steps")
    if not isinstance(steps, list) or not steps:
        raise BridgeError(400, "bad_request", "steps must be a non-empty list")
    order = _Order()
    lines: list[str] = []
    built = [_step(s, order, 0, lines, "", sport) for s in steps]
    extra: dict[str, Any] = {}
    if sport == "swimming":
        pool = _pos_num(body.get("pool_length_m", 25), "pool_length_m", 10, 100)
        extra = {"poolLength": pool, "poolLengthUnit": {"unitId": 1, "unitKey": "meter", "factor": 100.0}}
        lines.insert(0, f"Pool length {pool:g} m")
    st = _sport_type(sport)
    workout = BaseWorkout(
        workoutName=body["name"],
        description=body.get("description") or None,
        estimatedDurationInSecs=0,
        sportType=st,
        workoutSegments=[WorkoutSegment(segmentOrder=1, sportType=st, workoutSteps=built)],
        **extra,
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
    replace_id = None if body.get("workout_id") is None else _pos_int(body.get("workout_id"), "workout_id")

    try:
        if kind == "strength":
            sport = "strength_training"
            workout, lines = _build_strength(body)
        elif kind in ("run", "sport"):
            sport = "running" if kind == "run" else _resolve_sport(body.get("sport"))
            workout, lines = _build_sport(body, sport)
        else:
            raise BridgeError(400, "bad_request", 'kind must be "strength", "run" or "sport"')
    except ValueError as exc:  # pydantic validation
        raise BridgeError(400, "bad_request", f"invalid workout: {str(exc)[:300]}") from exc

    preview: dict[str, Any] = {
        "kind": kind, "sport": sport, "label": SPORTS[sport][3], "name": body["name"], "steps": lines,
        "schedule_date": schedule, "send_to_watch": send, "replace_workout_id": replace_id,
    }
    if body.get("dry_run", True):
        if replace_id:
            api = require_active()
            with _api_lock:
                preview["replace_name"] = _workout_name(api, replace_id)
        return {"status": "preview", "preview": preview}

    api = require_active()
    with _api_lock:
        if replace_id:
            preview["replace_name"] = _workout_name(api, replace_id)
            # PUT replaces the whole workout but keeps its id, so calendar
            # entries pointing at it stay where they are.
            api.update_workout(replace_id, workout.to_dict())
            workout_id = replace_id
            result: dict[str, Any] = {"status": "updated", "workout_id": workout_id, "preview": preview}
        else:
            created = api.upload_workout(workout.to_dict()) or {}
            workout_id = created.get("workoutId")
            if not workout_id:
                raise BridgeError(502, "garmin_unavailable", "Garmin accepted the request but returned no workout id")
            result = {"status": "created", "workout_id": workout_id, "preview": preview}
        # Follow-on steps report their own failure without hiding the saved workout.
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


# --- reading a workout back, any sport ---

_EX_NAME_BY_KEY = {(e["category"], e["exercise"]): e["name"] for e in exercises.EXERCISES}


def _pace_str(mps: float | None) -> str:
    if not mps:
        return "?"
    secs = int(round(1000 / mps))
    return f"{secs // 60}:{secs % 60:02d}"


def _describe_target(s: dict[str, Any], sport: str | None) -> str:
    key = g(s, "targetType", "workoutTargetTypeKey")
    if not key or key == "no.target":
        return ""
    z, a, b = s.get("zoneNumber"), num(s.get("targetValueOne")), num(s.get("targetValueTwo"))
    has_range = a is not None and b is not None
    if key == "heart.rate.zone":
        return f" in HR zone {z}" if z else (f" at {a:g}–{b:g} bpm" if has_range else "")
    if key == "power.zone":
        return f" in power zone {z}" if z else (f" at {a:g}–{b:g} W" if has_range else "")
    if key == "pace.zone" and has_range:
        return f" @ {_pace_str(max(a, b))}–{_pace_str(min(a, b))} /km"
    if key == "speed.zone" and has_range:
        return f" at {a * 3.6:.1f}–{b * 3.6:.1f} km/h"
    if key == "cadence" and has_range:
        return f" at {a:g}–{b:g} {'spm' if sport in PACE_SPORTS else 'rpm'}"
    return f" ({key})"


def _describe_step(s: Any, indent: str, lines: list[str], sport: str | None) -> None:
    if not isinstance(s, dict):
        return
    if s.get("type") == "RepeatGroupDTO" or g(s, "stepType", "stepTypeKey") == "repeat":
        n = s.get("numberOfIterations") or num(s.get("endConditionValue"))
        lines.append(f"{indent}Repeat {int(n) if n else '?'}×:")
        for child in sorted(s.get("workoutSteps") or [], key=lambda c: (c or {}).get("stepOrder") or 0):
            _describe_step(child, indent + "   ", lines, sport)
        return
    kind = str(g(s, "stepType", "stepTypeKey") or "step").capitalize()
    ex = ""
    if s.get("category"):
        cat, exn = s.get("category"), s.get("exerciseName") or ""
        ex = " " + (_EX_NAME_BY_KEY.get((cat, exn)) or str(exn or cat).replace("_", " ").title())
    ck, v = g(s, "endCondition", "conditionTypeKey"), num(s.get("endConditionValue"))
    if ck == "time" and v:
        length = _fmt_secs(v)
    elif ck == "distance" and v:
        length = f"{v / 1000:g} km" if v >= 1000 else f"{v:g} m"
    elif ck == "reps" and v:
        length = f"{int(v)} reps"
    elif ck == "calories" and v:
        length = f"{int(v)} kcal"
    elif ck == "lap.button":
        length = "until lap press"
    else:
        length = str(ck or "")
    load = ""
    wv, unit = num(s.get("weightValue")), g(s, "weightUnit", "unitKey")
    if wv:
        load = f" @ {wv:g} {'kg' if unit == 'kilogram' else (unit or '')}".rstrip()
    notes = s.get("description")
    lines.append(f"{indent}{kind}{ex} {length}{load}{_describe_target(s, sport)}".rstrip() + (f" — {notes}" if notes else ""))


def h_workouts_detail(body: dict[str, Any]) -> dict[str, Any]:
    workout_id = _pos_int(body.get("workout_id"), "workout_id")
    api = require_active()
    with _api_lock:
        try:
            w = api.get_workout_by_id(workout_id) or {}
        except Exception as exc:  # noqa: BLE001
            err = translate(exc)
            if err.status in (401, 429):
                raise err from exc
            raise BridgeError(404, "not_found", f"No workout {workout_id} in your Garmin library") from exc
    sport = g(w, "sportType", "sportTypeKey")
    lines: list[str] = []
    for seg in sorted(w.get("workoutSegments") or [], key=lambda x: (x or {}).get("segmentOrder") or 0):
        seg_sport = g(seg, "sportType", "sportTypeKey") or sport
        if len(w.get("workoutSegments") or []) > 1:
            lines.append(f"Segment {seg.get('segmentOrder')} ({seg_sport}):")
        for step in sorted(seg.get("workoutSteps") or [], key=lambda x: (x or {}).get("stepOrder") or 0):
            _describe_step(step, "", lines, seg_sport)
    pool = num(w.get("poolLength"))
    return {
        "workout_id": w.get("workoutId") or workout_id,
        "name": w.get("workoutName"),
        "sport": sport,
        "description": w.get("description"),
        "pool_length_m": pool,
        "estimated_duration_s": num(w.get("estimatedDurationInSecs")),
        "updated": w.get("updatedDate") or w.get("createdDate"),
        "steps": lines,
    }


def h_workouts_list(body: dict[str, Any]) -> dict[str, Any]:
    api = require_active()
    months = body.get("months")
    if not isinstance(months, list) or not months:
        raise BridgeError(400, "bad_request", "months must be a list of [year, month]")
    with _api_lock:
        limit = _pos_int(body.get("limit", 30), "limit", 1, 100)
        library = api.get_workouts(0, limit) or []
        scheduled: list[dict[str, Any]] = []
        seen: set[Any] = set()  # month views overlap at the edges (late Oct shows in Nov too)
        for pair in months[:3]:
            if not (isinstance(pair, list) and len(pair) == 2):
                continue
            year, month = _pos_int(pair[0], "year", 2000, 2100), _pos_int(pair[1], "month", 1, 12)
            items = g(api.get_scheduled_workouts(year, month), "calendarItems") or []
            for it in items:
                if isinstance(it, dict) and it.get("itemType") == "workout":
                    if it.get("id") in seen:
                        continue
                    seen.add(it.get("id"))
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


# ------------------------------------------------------------ nutrition ---
#
# Garmin Connect+ food logging. python-garminconnect only wraps the reads, so
# the writes call nutrition-service directly. The contract (PUT with a
# mealDate + foodLogItems envelope, per-date numeric mealId, servingQty, and a
# GARMIN/FATSECRET source namespace) follows garmin_mcp (MIT, Taxuspt), which
# writes to real accounts under live end-to-end tests, and was independently
# confirmed by GarminFood (MIT, mlcousek). Every write supports dry_run.

MEAL_NAMES = ("BREAKFAST", "LUNCH", "DINNER", "SNACKS")
NUTRITION_REGION = os.environ.get("GARMIN_NUTRITION_REGION", "US")
NUTRITION_LANGUAGE = os.environ.get("GARMIN_NUTRITION_LANGUAGE", "en")
TIME_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d(:[0-5]\d)?$")


def _num_str(value: float) -> str:
    """Garmin wants nutrient numbers as strings, '160' not '160.0'."""
    return str(int(value)) if float(value) == int(value) else str(round(float(value), 3))


def _api_put(api: Garmin, path: str, payload: dict[str, Any]) -> Any:
    resp = api.client.put("connectapi", path, json=payload)
    return _resp_json(resp)


def _api_delete(api: Garmin, path: str, payload: dict[str, Any]) -> Any:
    resp = api.client.delete("connectapi", path, json=payload)
    return _resp_json(resp)


def _resp_json(resp: Any) -> Any:
    try:
        return resp.json() if hasattr(resp, "json") else None
    except Exception:  # noqa: BLE001 — 200 with an empty body
        return None


def _source_for(food_id: str, given: Any) -> str:
    """Custom (GARMIN) food ids are 32-char hex; FatSecret ids are numeric."""
    if isinstance(given, str) and given.upper() in ("GARMIN", "FATSECRET"):
        return given.upper()
    return "FATSECRET" if food_id.isdigit() else "GARMIN"


def _now_local_hms() -> str:
    return time.strftime("%H:%M:%S", time.localtime())  # TZ is the owner's zone


def _hms(value: str) -> str:
    return value if len(value) == 8 else f"{value}:00"


def _meals(api: Garmin, day: str) -> list[dict[str, Any]]:
    data = api.connectapi(f"/nutrition-service/meals/{day}") or {}
    meals = [m for m in (data.get("meals") or []) if isinstance(m, dict) and m.get("mealId") is not None]
    if not meals:
        raise BridgeError(409, "no_meals", f"Garmin returned no meals for {day} — is Connect+ nutrition switched on?")
    return meals


def _resolve_meal(meals: list[dict[str, Any]], meal: Any, at: Any) -> tuple[dict[str, Any], str]:
    """Pick the meal instance and a mealTime Garmin will file under it.

    A named meal with a time window uses the given time if it falls inside,
    else the window start (what the official app does). Snacks have no window:
    use the given/current time, nudged just past any meal window it falls in,
    since Garmin also matches meals by mealTime.
    """
    when = None
    if at is not None:
        if not isinstance(at, str) or not TIME_RE.match(at):
            raise BridgeError(400, "bad_request", "time must be HH:MM or HH:MM:SS")
        when = _hms(at)

    def window(m: dict[str, Any]) -> tuple[str, str] | None:
        st, en = m.get("startTime"), m.get("endTime")
        return (st, en) if isinstance(st, str) and isinstance(en, str) else None

    if meal is None:
        when = when or _now_local_hms()
        target = next((m for m in meals if window(m) and window(m)[0] <= when <= window(m)[1]), None)
        target = target or next((m for m in meals if m.get("mealName") == "SNACKS"), None)
        if target is None:
            raise BridgeError(409, "no_meals", "Couldn't match a meal for that time")
        return target, when

    name = str(meal).upper()
    if name == "SNACK":
        name = "SNACKS"
    if name not in MEAL_NAMES:
        raise BridgeError(400, "bad_request", f"meal must be one of {', '.join(MEAL_NAMES)}")
    target = next((m for m in meals if m.get("mealName") == name), None)
    if target is None:
        raise BridgeError(409, "no_meals", f"No {name} meal on that date in Garmin")
    w = window(target)
    if w:
        return target, when if when and w[0] <= when <= w[1] else w[0]
    when = when or _now_local_hms()
    for m in meals:
        mw = window(m)
        if mw and mw[0] <= when <= mw[1]:
            h, mi, se = (int(x) for x in mw[1].split(":"))
            nxt = min(h * 3600 + mi * 60 + se + 60, 86399)
            when = f"{nxt // 3600:02d}:{(nxt % 3600) // 60:02d}:{nxt % 60:02d}"
    return target, when


def _log_stamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())


def _norm_serving(s: dict[str, Any]) -> dict[str, Any]:
    out = {
        "serving_id": s.get("servingId"),
        "unit": s.get("servingUnit"),
        "units": num(s.get("numberOfUnits")) if not isinstance(s.get("numberOfUnits"), str) else s.get("numberOfUnits"),
        "kcal": s.get("calories"),
        "protein_g": s.get("protein"),
        "carbs_g": s.get("carbs"),
        "fat_g": s.get("fat"),
        "fiber_g": s.get("fiber"),
        "sugar_g": s.get("sugar"),
        "sodium_mg": s.get("sodium"),
    }
    return {k: v for k, v in out.items() if v is not None}


def _norm_food(item: dict[str, Any], custom: bool) -> dict[str, Any]:
    meta = _as_dict(item.get("foodMetaData")) or item
    out = {
        "food_id": str(meta.get("foodId")) if meta.get("foodId") is not None else None,
        "name": meta.get("foodName"),
        "brand": meta.get("brandName"),
        "source": meta.get("source") or ("GARMIN" if custom else None),
        "region": meta.get("regionCode"),
        "language": meta.get("languageCode"),
        "mine": custom,
        "servings": [_norm_serving(s) for s in item.get("nutritionContents") or [] if isinstance(s, dict)],
    }
    return {k: v for k, v in out.items() if v is not None}


def h_food_search(body: dict[str, Any]) -> dict[str, Any]:
    query = body.get("query")
    if not isinstance(query, str) or not query.strip():
        raise BridgeError(400, "bad_request", "query is required")
    limit = _pos_int(body.get("limit", 15), "limit", 1, 50)
    api = require_active()
    results: list[dict[str, Any]] = []
    errors: dict[str, str] = {}
    with _api_lock:
        if body.get("include_custom", True):
            try:
                mine = api.connectapi("/nutrition-service/customFood", params={
                    "searchExpression": query.strip(), "start": 0, "limit": limit, "includeContent": "true"}) or {}
                results += [_norm_food(f, True) for f in mine.get("customFoods") or [] if isinstance(f, dict)]
            except (GarminConnectAuthenticationError, GarminConnectTooManyRequestsError):
                raise
            except Exception as exc:  # noqa: BLE001
                errors["custom"] = translate(exc).message
            time.sleep(CALL_GAP_S)
        data = api.connectapi("/nutrition-service/food/search", params={
            "searchExpression": query.strip(), "start": 0, "limit": limit}) or {}
    results += [_norm_food(f, False) for f in (data.get("results") or []) if isinstance(f, dict)]
    return {"results": results, "more": bool(data.get("moreDataAvailable")), "errors": errors}


def h_food_day(body: dict[str, Any]) -> dict[str, Any]:
    """Live read of one day's food log, meal windows and nutrition goals."""
    day = _date(body.get("date"), "date")
    api = require_active()
    out: dict[str, Any] = {"date": day}
    with _api_lock:
        out["log"] = api.connectapi(f"/nutrition-service/food/logs/{day}")
        time.sleep(CALL_GAP_S)
        try:
            out["settings"] = api.connectapi(f"/nutrition-service/settings/{day}")
        except (GarminConnectAuthenticationError, GarminConnectTooManyRequestsError):
            raise
        except Exception as exc:  # noqa: BLE001
            out["settings"] = None
            out["settings_error"] = translate(exc).message
    return out


def h_food_log_add(body: dict[str, Any]) -> dict[str, Any]:
    """Log catalog or custom foods (by id + serving) to one meal."""
    day = _date(body.get("date"), "date")
    items = body.get("items")
    if not isinstance(items, list) or not 1 <= len(items) <= 30:
        raise BridgeError(400, "bad_request", "items must be a list of 1–30 foods")
    built: list[dict[str, Any]] = []
    for i, it in enumerate(items, 1):
        if not isinstance(it, dict):
            raise BridgeError(400, "bad_request", f"item {i} must be an object")
        food_id, serving_id = it.get("food_id"), it.get("serving_id")
        if not isinstance(food_id, (str, int)) or not str(food_id).strip() or not isinstance(serving_id, (str, int)) or not str(serving_id).strip():
            raise BridgeError(400, "bad_request", f"item {i} needs food_id and serving_id (from garmin_food_search)")
        qty = _pos_num(it.get("servings", 1), f"item {i} servings", 0.01, 100)
        fid = str(food_id).strip()
        built.append({
            "food_id": fid, "serving_id": str(serving_id).strip(), "servings": round(qty, 3),
            "source": _source_for(fid, it.get("source")),
            "region": it.get("region") if isinstance(it.get("region"), str) and it.get("region") else NUTRITION_REGION,
            "language": it.get("language") if isinstance(it.get("language"), str) and it.get("language") else NUTRITION_LANGUAGE,
            "label": str(it.get("label"))[:80] if it.get("label") else None,
        })
    api = require_active()
    with _api_lock:
        meal, meal_time = _resolve_meal(_meals(api, day), body.get("meal"), body.get("time"))
        preview = {"date": day, "meal": meal.get("mealName"), "meal_time": meal_time, "items": built}
        if body.get("dry_run", True):
            return {"status": "preview", "preview": preview}
        stamp = _log_stamp()
        payload = {"mealDate": day, "foodLogItems": [{
            "logTimestamp": stamp, "logSource": "GCW", "logCategory": "REGULAR_LOG", "mealTime": meal_time,
            "action": "ADD", "mealId": meal["mealId"], "foodId": b["food_id"], "servingId": b["serving_id"],
            "source": b["source"], "regionCode": b["region"], "languageCode": b["language"], "servingQty": b["servings"],
        } for b in built]}
        resp = _api_put(api, "/nutrition-service/food/logs", payload)
    return {"status": "logged", "preview": preview, "response": resp}


def _quick_items(items: Any) -> list[dict[str, Any]]:
    if not isinstance(items, list) or not 1 <= len(items) <= 30:
        raise BridgeError(400, "bad_request", "items must be a list of 1–30 entries")
    out = []
    for i, it in enumerate(items, 1):
        if not isinstance(it, dict):
            raise BridgeError(400, "bad_request", f"item {i} must be an object")
        name = it.get("name")
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 100:
            raise BridgeError(400, "bad_request", f"item {i} needs a name (max 100 characters)")
        out.append({
            "name": name.strip(),
            "kcal": _pos_num(it.get("calories"), f"item {i} calories", 0, 10000),
            "protein_g": _pos_num(it.get("protein", 0), f"item {i} protein", 0, 1000),
            "carbs_g": _pos_num(it.get("carbs", 0), f"item {i} carbs", 0, 2000),
            "fat_g": _pos_num(it.get("fat", 0), f"item {i} fat", 0, 1000),
        })
    return out


def _quick_payload(day: str, meal: dict[str, Any], meal_time: str, items: list[dict[str, Any]]) -> dict[str, Any]:
    stamp = _log_stamp()
    return {"mealDate": day, "quickAddItems": [{
        "name": q["name"], "logId": None, "logTimestamp": stamp, "logSource": "GCW", "logCategory": "QUICK_ADD",
        "mealTime": meal_time, "mealId": meal["mealId"], "action": "ADD",
        "calories": _num_str(q["kcal"]), "carbs": _num_str(q["carbs_g"]), "protein": _num_str(q["protein_g"]), "fat": _num_str(q["fat_g"]),
    } for q in items]}


def h_food_quick_add(body: dict[str, Any]) -> dict[str, Any]:
    """Quick-add entries by name + calories/macros (no catalog food needed)."""
    day = _date(body.get("date"), "date")
    items = _quick_items(body.get("items"))
    api = require_active()
    with _api_lock:
        meal, meal_time = _resolve_meal(_meals(api, day), body.get("meal"), body.get("time"))
        preview = {"date": day, "meal": meal.get("mealName"), "meal_time": meal_time, "items": items}
        if body.get("dry_run", True):
            return {"status": "preview", "preview": preview}
        resp = _api_put(api, "/nutrition-service/food/logs/quickAdd", _quick_payload(day, meal, meal_time, items))
    return {"status": "logged", "preview": preview, "response": resp}


_CUSTOM_NUTRIENTS = {
    "protein": "protein", "carbs": "carbs", "fat": "fat", "fiber": "fiber", "sugar": "sugar",
    "saturated_fat": "saturatedFat", "trans_fat": "transFat", "sodium": "sodium", "cholesterol": "cholesterol",
    "potassium": "potassium", "calcium": "calcium", "iron": "iron", "vitamin_d": "vitaminD",
}


def _find_custom(api: Garmin, name: str) -> dict[str, Any] | None:
    data = api.connectapi("/nutrition-service/customFood", params={
        "searchExpression": name, "start": 0, "limit": 20, "includeContent": "true"}) or {}
    for f in data.get("customFoods") or []:
        if isinstance(f, dict) and str(_as_dict(f.get("foodMetaData")).get("foodName", "")).lower() == name.lower():
            return _norm_food(f, True)
    return None


def h_custom_food_create(body: dict[str, Any]) -> dict[str, Any]:
    name = body.get("name")
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 100:
        raise BridgeError(400, "bad_request", "name is required (max 100 characters)")
    name = name.strip()
    unit = body.get("serving_unit") or "G"
    if not isinstance(unit, str) or not re.match(r"^[A-Za-z_ ]{1,20}$", unit):
        raise BridgeError(400, "bad_request", "serving_unit must be a unit like G, ML, OZ, CUP, PIECE")
    units = _pos_num(body.get("serving_size", 100), "serving_size", 0.01, 10000)
    nutrition: dict[str, Any] = {"servingUnit": unit.upper(), "numberOfUnits": _num_str(units),
                                 "calories": _num_str(_pos_num(body.get("calories"), "calories", 0, 10000))}
    for key, garmin_key in _CUSTOM_NUTRIENTS.items():
        if body.get(key) is not None:
            nutrition[garmin_key] = _num_str(_pos_num(body.get(key), key, 0, 100000))
    meta: dict[str, Any] = {"foodName": name, "foodType": "GENERIC", "source": "GARMIN",
                            "regionCode": NUTRITION_REGION, "languageCode": NUTRITION_LANGUAGE}
    if isinstance(body.get("brand"), str) and body["brand"].strip():
        meta["brandName"] = body["brand"].strip()[:100]
    api = require_active()
    with _api_lock:
        existing = _find_custom(api, name)
        preview = {"name": name, "brand": meta.get("brandName"), "per_serving": nutrition, "existing": existing}
        if body.get("dry_run", True):
            return {"status": "preview", "preview": preview}
        resp = _api_put(api, "/nutrition-service/customFood", {"foodMetaData": meta, "nutritionContents": [nutrition]})
        food = _norm_food(resp, True) if isinstance(resp, dict) and resp else None
        if not food or not food.get("food_id") or not food.get("servings"):
            time.sleep(CALL_GAP_S)
            food = _find_custom(api, name)  # 204: look it up by name
    return {"status": "created", "preview": preview, "food": food}


def h_food_log_delete(body: dict[str, Any]) -> dict[str, Any]:
    day = _date(body.get("date"), "date")
    ids = body.get("log_ids")
    if not isinstance(ids, list) or not ids or not all(isinstance(i, str) and re.match(r"^[A-Za-z0-9_-]{1,64}$", i) for i in ids):
        raise BridgeError(400, "bad_request", "log_ids must be a list of log ids from garmin_food_log")
    api = require_active()
    with _api_lock:
        log = api.connectapi(f"/nutrition-service/food/logs/{day}") or {}
        found = {}
        for md in log.get("mealDetails") or []:
            for f in (md or {}).get("loggedFoods") or []:
                if isinstance(f, dict) and f.get("logId") in ids:
                    found[f["logId"]] = {
                        "log_id": f["logId"],
                        "meal": _as_dict(md.get("meal")).get("mealName"),
                        "name": _as_dict(f.get("foodMetaData")).get("foodName") or f.get("name"),
                    }
        missing = [i for i in ids if i not in found]
        if missing:
            raise BridgeError(404, "not_found", f"Not in the {day} food log: {', '.join(missing)}")
        preview = {"date": day, "entries": list(found.values())}
        if body.get("dry_run", True):
            return {"status": "preview", "preview": preview}
        _api_delete(api, f"/nutrition-service/food/logs/{day}", {"logIds": ids})
    return {"status": "deleted", "preview": preview}


def h_food_copy_day(body: dict[str, Any]) -> dict[str, Any]:
    """Re-log one day's entries (optionally some meals only) onto another date."""
    src, dst = _date(body.get("from_date"), "from_date"), _date(body.get("to_date"), "to_date")
    if src == dst:
        raise BridgeError(400, "bad_request", "from_date and to_date must differ")
    only = body.get("meals")
    only_set = {str(m).upper() for m in only} if isinstance(only, list) and only else None
    api = require_active()
    with _api_lock:
        log = api.connectapi(f"/nutrition-service/food/logs/{src}") or {}
        time.sleep(CALL_GAP_S)
        dst_meals = _meals(api, dst)
        regular: list[dict[str, Any]] = []
        quick: list[tuple[dict[str, Any], str, dict[str, Any]]] = []
        lines: list[dict[str, Any]] = []
        for md in log.get("mealDetails") or []:
            meal_name = _as_dict((md or {}).get("meal")).get("mealName")
            if not meal_name or (only_set and meal_name not in only_set):
                continue
            target, meal_time = _resolve_meal(dst_meals, meal_name, None)
            for f in (md or {}).get("loggedFoods") or []:
                if not isinstance(f, dict):
                    continue
                meta, nc = _as_dict(f.get("foodMetaData")), _as_dict(f.get("nutritionContent"))
                qty = num(f.get("servingQty")) or 1
                name = meta.get("foodName") or f.get("name") or "entry"
                if f.get("logCategory") == "QUICK_ADD" or not meta.get("foodId") or not nc.get("servingId"):
                    q = {"name": str(name)[:100], "kcal": (num(nc.get("calories")) or num(f.get("calories")) or 0) * qty,
                         "protein_g": (num(nc.get("protein")) or num(f.get("protein")) or 0) * qty,
                         "carbs_g": (num(nc.get("carbs")) or num(f.get("carbs")) or 0) * qty,
                         "fat_g": (num(nc.get("fat")) or num(f.get("fat")) or 0) * qty}
                    quick.append((target, meal_time, q))
                else:
                    fid = str(meta["foodId"])
                    regular.append({"meal": target, "meal_time": meal_time, "food_id": fid, "serving_id": str(nc.get("servingId")),
                                    "source": _source_for(fid, meta.get("source")), "region": meta.get("regionCode") or NUTRITION_REGION,
                                    "language": meta.get("languageCode") or NUTRITION_LANGUAGE, "servings": qty})
                lines.append({"meal": meal_name, "name": name, "servings": qty, "kcal": (num(nc.get("calories")) or 0) * qty})
        if not lines:
            raise BridgeError(404, "not_found", f"Nothing to copy from {src}" + (f" for {', '.join(sorted(only_set))}" if only_set else ""))
        preview = {"from_date": src, "to_date": dst, "entries": lines}
        if body.get("dry_run", True):
            return {"status": "preview", "preview": preview}
        stamp = _log_stamp()
        if regular:
            _api_put(api, "/nutrition-service/food/logs", {"mealDate": dst, "foodLogItems": [{
                "logTimestamp": stamp, "logSource": "GCW", "logCategory": "REGULAR_LOG", "mealTime": r["meal_time"], "action": "ADD",
                "mealId": r["meal"]["mealId"], "foodId": r["food_id"], "servingId": r["serving_id"], "source": r["source"],
                "regionCode": r["region"], "languageCode": r["language"], "servingQty": r["servings"]} for r in regular]})
        if quick:
            time.sleep(CALL_GAP_S)
            _api_put(api, "/nutrition-service/food/logs/quickAdd", {"mealDate": dst, "quickAddItems": [{
                "name": q["name"], "logId": None, "logTimestamp": stamp, "logSource": "GCW", "logCategory": "QUICK_ADD",
                "mealTime": mt, "mealId": m["mealId"], "action": "ADD", "calories": _num_str(q["kcal"]),
                "carbs": _num_str(q["carbs_g"]), "protein": _num_str(q["protein_g"]), "fat": _num_str(q["fat_g"])} for m, mt, q in quick]})
    return {"status": "copied", "preview": preview}


ROUTES = {
    "/status": h_status,
    "/session/load": h_load,
    "/login": h_login,
    "/login/mfa": h_login_mfa,
    "/daily": h_daily,
    "/activities": h_activities,
    "/activity/detail": h_activity_detail,
    "/profile": h_profile,
    "/food/search": h_food_search,
    "/food/day": h_food_day,
    "/food/log/add": h_food_log_add,
    "/food/quick_add": h_food_quick_add,
    "/food/custom/create": h_custom_food_create,
    "/food/log/delete": h_food_log_delete,
    "/food/copy_day": h_food_copy_day,
    "/workouts/list": h_workouts_list,
    "/workouts/create": h_workouts_create,
    "/workouts/schedule": h_workouts_schedule,
    "/workouts/unschedule": h_workouts_unschedule,
    "/workouts/delete": h_workouts_delete,
    "/workouts/detail": h_workouts_detail,
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
