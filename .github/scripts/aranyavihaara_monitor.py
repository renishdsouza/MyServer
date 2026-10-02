#!/usr/bin/env python3

import json
import os
import sys
from pathlib import Path
from urllib.parse import unquote

import requests

BASE_URL = "https://aranyavihaara.karnataka.gov.in"
TREKS_URL = f"{BASE_URL}/get-treks"
DISTRICT_ID = os.getenv("DISTRICT_ID", "24")
STATE_FILE = Path(os.getenv("STATE_FILE", ".github/monitor-state/aranyavihaara_treks.json"))

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")


def log(message: str) -> None:
    print(message, flush=True)


def send_telegram(message: str) -> bool:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        log("Telegram secrets are missing. Skipping Telegram alert.")
        return False

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"

    try:
        response = requests.post(
            url,
            data={"chat_id": TELEGRAM_CHAT_ID, "text": message},
            timeout=20,
        )
        response.raise_for_status()
        data = response.json()
        if not data.get("ok"):
            log(f"Telegram API error: {data}")
            return False
        return True
    except requests.RequestException as exc:
        log(f"Telegram request failed: {exc}")
        return False


def create_session() -> requests.Session:
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) "
                "Gecko/20100101 Firefox/140.0"
            ),
            "Accept": "*/*",
        }
    )
    return session


def get_treks(session: requests.Session) -> list[dict]:
    page = session.get(BASE_URL + "/", timeout=30)
    page.raise_for_status()

    xsrf_token = session.cookies.get("XSRF-TOKEN")

    headers = {
        "X-Requested-With": "XMLHttpRequest",
        "Referer": BASE_URL + "/",
        "Origin": BASE_URL,
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    }

    if xsrf_token:
        headers["X-XSRF-TOKEN"] = unquote(xsrf_token)

    response = session.post(
        TREKS_URL,
        headers=headers,
        data={"district_id": DISTRICT_ID},
        timeout=30,
    )
    response.raise_for_status()

    data = response.json()
    if not isinstance(data, list):
        raise ValueError(f"Unexpected API response: {type(data).__name__}")

    return data


def trek_key(trek: dict) -> str:
    trek_id = trek.get("id")
    if trek_id is not None:
        return str(trek_id)
    return (trek.get("name") or "").strip().lower()


def normalized_state(treks: list[dict]) -> dict:
    state: dict[str, dict] = {}
    for trek in treks:
        key = trek_key(trek)
        if not key:
            continue

        state[key] = {
            "id": trek.get("id"),
            "name": trek.get("name"),
            "name_kn": trek.get("name_kn"),
            "updated_at": trek.get("updated_at"),
            "created_at": trek.get("created_at"),
            "distance": trek.get("distance"),
            "duration": trek.get("duration"),
            "start_point": trek.get("start_point"),
            "end_point": trek.get("end_point"),
            "is_active": trek.get("is_active"),
        }
    return state


def load_state() -> dict:
    if not STATE_FILE.exists():
        return {}

    try:
        with STATE_FILE.open("r", encoding="utf-8") as file:
            data = json.load(file)
        if isinstance(data, dict):
            return data
    except (OSError, json.JSONDecodeError) as exc:
        log(f"Could not read state file: {exc}")

    return {}


def save_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp_file = STATE_FILE.with_suffix(".tmp")

    with tmp_file.open("w", encoding="utf-8") as file:
        json.dump(state, file, indent=2, ensure_ascii=False)

    tmp_file.replace(STATE_FILE)


def format_trek(trek: dict) -> str:
    name = trek.get("name") or "Unnamed trek"
    trek_id = trek.get("id", "unknown")

    lines = [
        "🌲 NEW TREK DETECTED!",
        "",
        f"🥾 {name}",
        f"🆔 ID: {trek_id}",
    ]

    if trek.get("distance"):
        lines.append(f"📏 Distance: {trek['distance']} km")
    if trek.get("duration"):
        lines.append(f"⏱ Duration: {trek['duration']}")
    if trek.get("start_point"):
        lines.append(f"📍 Start: {trek['start_point']}")
    if trek.get("end_point"):
        lines.append(f"🏁 End: {trek['end_point']}")
    if trek.get("created_at"):
        lines.append(f"📅 Created: {trek['created_at']}")
    if trek.get("updated_at"):
        lines.append(f"🔄 Updated: {trek['updated_at']}")

    lines.extend(["", f"🌐 {BASE_URL}/"])
    return "\n".join(lines)


def main() -> int:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        log("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID are required.")
        return 2

    session = create_session()
    treks = get_treks(session)

    if not treks:
        log("API returned zero treks.")
        return 1

    previous = load_state()
    current = normalized_state(treks)

    if not previous:
        save_state(current)
        log(f"Initial state saved: {len(current)} treks.")
        return 0

    new_keys = [key for key in current if key not in previous]

    if not new_keys:
        log(f"No new treks. Current count: {len(current)}")
        return 0

    log(f"NEW TREKS FOUND: {len(new_keys)}")

    sent_count = 0
    for key in new_keys:
        trek = current[key]
        message = format_trek(trek)
        if send_telegram(message):
            sent_count += 1

    log(f"Telegram alerts sent: {sent_count}/{len(new_keys)}")
    save_state(current)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except requests.RequestException as exc:
        log(f"Request failed: {type(exc).__name__}: {exc}")
        raise SystemExit(1)
