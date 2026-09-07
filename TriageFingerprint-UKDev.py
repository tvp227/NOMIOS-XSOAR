import json
import re
import hashlib
from CommonServerPython import *

# TRIAGEFINGERPRINT-UKDEV
# STABLE ID FOR "THIS RULE, FIRING ON THESE THINGS". RECURRENCE IS COUNTED ON THIS, NOT
# ON THE RULE NAME, SO A RULE THAT FIRES ON TEN DIFFERENT USERS IS NOT RECURRING BUT THE
# SAME USER TEN TIMES IS.
#
# URL AND DOMAIN ARE DELIBERATELY EXCLUDED. THEY ARE THE NOISIEST AND LEAST STABLE
# ENTITIES, AND INCLUDING THEM MEANS ALMOST NOTHING EVER MATCHES TWICE.

PRIMARY = ("account", "accounts", "user", "upn",
           "ip", "ips", "ipaddress",
           "host", "hosts", "hostname", "machine",
           "filehash", "filehashes", "hash", "sha256")

IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
HASH = re.compile(r"^[A-Fa-f0-9]{32,64}$")
URLISH = re.compile(r"^(https?://|www\.)", re.I)
DOMAIN = re.compile(r"^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")


def is_primary(value):
    # NO TYPE ON THE ENTITY, SO FINGERPRINT IT THE SAME WAY THE EXTRACTION SCRIPT DOES
    v = str(value).strip()
    if URLISH.match(v):
        return False
    if "@" in v or IPV4.match(v) or HASH.match(v):
        return True
    return not DOMAIN.match(v)   # BARE HOSTNAMES COUNT, DOMAINS DO NOT


def harvest(obj, out, typed=None):
    if isinstance(obj, list):
        for i in obj:
            harvest(i, out, typed)
    elif isinstance(obj, dict):
        low = {str(k).lower(): v for k, v in obj.items()}
        if "value" in low and ("type" in low or "kind" in low):
            t = str(low.get("type") or low.get("kind")).lower()
            if t in PRIMARY:
                out.append(str(low["value"]))
            return
        for k, v in low.items():
            harvest(v, out, k if k in PRIMARY else None)
    elif obj not in (None, ""):
        if typed in PRIMARY or (typed is None and is_primary(obj)):
            out.append(str(obj))


def main():
    args = demisto.args()
    rule = (args.get("rule_name") or "").strip().lower()

    raw = args.get("entities")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except Exception:
            raw = [x.strip() for x in raw.split(",") if x.strip()]

    values = []
    harvest(raw, values)
    values = sorted({v.strip().lower() for v in values if v and v.strip()})

    seed = rule + "|" + "|".join(values)
    fp = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]

    return_results(CommandResults(
        readable_output="Triage fingerprint `%s` from %d primary entities." % (fp, len(values)),
        outputs_prefix="TriageFingerprint",
        outputs_key_field="Value",
        outputs={"Value": fp, "Rule": rule, "Entities": values},
    ))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
