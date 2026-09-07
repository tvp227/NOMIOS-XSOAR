import json
import re
import hashlib
from CommonServerPython import *

# INVESTIGATIONPACK-UKDEV
# RUNS ONE COMPOSITE KQL PER ENTITY AGAINST LOG ANALYTICS AND RETURNS A SMALL TYPED OBJECT.
# ONE PLAYBOOK TASK, NO LOOP. NOTHING IN HERE IS ALLOWED TO RAISE.
#
# WHY COMPOSITE: SIX SEPARATE QUERIES PER ENTITY IS FORTY ROUND TRIPS ON A BUSY INCIDENT.
# UNION ISFUZZY=TRUE GETS THE SAME ANSWERS IN ONE CALL AND SURVIVES A WORKSPACE THAT DOES
# NOT COLLECT ONE OF THE TABLES, WHICH IS THE NORMAL CASE ACROSS AN MSSP ESTATE.

MAX_ROWS = 5          # ROWS KEPT PER LEG IN THE DISTILLED OBJECT
MAX_CELL = 80         # CHARACTERS PER CELL
TAKE = 50             # KQL CAP PER LEG
EGRESS_ACCOUNTS = 20  # DISTINCT ACCOUNTS BEFORE AN IP IS CALLED CORPORATE EGRESS

IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
SHA256 = re.compile(r"^[A-Fa-f0-9]{64}$")
SHA1_MD5 = re.compile(r"^([A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})$")
URLISH = re.compile(r"^(https?://|www\.)", re.I)
DOMAIN = re.compile(r"^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")


# ---------- ENTITY NORMALISATION ----------
# THE SENTINEL EXTRACTION SCRIPT HAS SHIPPED IN A FEW SHAPES. TAKE ALL OF THEM, AND
# FINGERPRINT ANYTHING STILL UNTYPED THE SAME WAY THE EXTRACTION SCRIPT DOES.

TYPE_ALIASES = {
    "account": "Account", "accounts": "Account", "user": "Account", "upn": "Account",
    "ip": "IP", "ips": "IP", "ipaddress": "IP", "address": "IP",
    "host": "Host", "hosts": "Host", "hostname": "Host", "machine": "Host",
    "filehash": "FileHash", "filehashes": "FileHash", "hash": "FileHash", "sha256": "FileHash",
    "url": "URL", "urls": "URL",
    "domain": "Domain", "domains": "Domain", "dnsresolution": "Domain",
}


def sniff(value):
    v = str(value).strip()
    if IPV4.match(v):
        return "IP"
    if SHA256.match(v) or SHA1_MD5.match(v):
        return "FileHash"
    if URLISH.match(v):
        return "URL"
    if "@" in v:
        return "Account"
    if DOMAIN.match(v):
        return "Domain"
    return "Host"


def normalise(raw):
    """RETURNS A LIST OF (TYPE, VALUE), DEDUPED, ORDER PRESERVED."""
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except Exception:
            raw = [x.strip() for x in raw.split(",") if x.strip()]

    pairs = []

    def push(t, v):
        v = str(v).strip()
        if v and (t, v.lower()) not in [(a, b.lower()) for a, b in pairs]:
            pairs.append((t, v))

    def walk(obj):
        if isinstance(obj, list):
            for i in obj:
                walk(i)
        elif isinstance(obj, dict):
            low = {str(k).lower(): v for k, v in obj.items()}
            # SHAPE A: {"Type": "...", "Value": "..."}
            if "value" in low and ("type" in low or "kind" in low):
                t = TYPE_ALIASES.get(str(low.get("type") or low.get("kind")).lower())
                push(t or sniff(low["value"]), low["value"])
                return
            # SHAPE B: TYPED BUCKETS {"Accounts": [...], "IPs": [...]}
            hit = False
            for k, v in low.items():
                if k in TYPE_ALIASES and isinstance(v, (list, str)):
                    hit = True
                    walk_typed(TYPE_ALIASES[k], v)
            if hit:
                return
            # SHAPE C: {"Values": [...]} OR ANYTHING ELSE, RECURSE
            for v in low.values():
                walk(v)
        elif obj not in (None, ""):
            push(sniff(obj), obj)

    def walk_typed(t, v):
        if isinstance(v, list):
            for i in v:
                if isinstance(i, dict):
                    walk(i)
                elif i:
                    push(t, i)
        elif v:
            push(t, v)

    walk(raw)
    return pairs


# ---------- KQL ----------
# EACH LEG PROJECTS THE SAME THREE COLUMNS SO ONE PARSER HANDLES EVERY ENTITY TYPE.

def kql_account(v):
    return """let W = 7d;
let A = "%(v)s";
union isfuzzy=true
(SigninLogs | where TimeGenerated > ago(W) | where UserPrincipalName =~ A or UserDisplayName =~ A
 | summarize Cnt=count() by Leg="SIGNIN", Key=strcat(iff(ResultType=="0","SUCCESS","FAIL:"), tostring(ResultType), " | ", AppDisplayName, " | ", tostring(Location), " | ", tostring(IPAddress), " | MFA=", tostring(AuthenticationRequirement)) | take %(t)d),
(SigninLogs | where TimeGenerated > ago(W) | where UserPrincipalName =~ A | where ResultType != "0"
 | summarize Cnt=count() by Leg="SIGNIN_FAIL", Key=strcat(tostring(ResultType), " | ", ResultDescription) | take %(t)d),
(SigninLogs | where TimeGenerated > ago(W) | where UserPrincipalName =~ A
 | where tostring(Location) !in ((SigninLogs | where TimeGenerated between (ago(30d) .. ago(W)) | where UserPrincipalName =~ A | distinct tostring(Location)))
 | summarize Cnt=count() by Leg="NEW_COUNTRY", Key=tostring(Location) | take %(t)d),
(SigninLogs | where TimeGenerated > ago(W) | where UserPrincipalName =~ A
 | where tostring(DeviceDetail.deviceId) !in ((SigninLogs | where TimeGenerated between (ago(30d) .. ago(W)) | where UserPrincipalName =~ A | distinct tostring(DeviceDetail.deviceId)))
 | summarize Cnt=count() by Leg="NEW_DEVICE", Key=strcat(tostring(DeviceDetail.displayName), " | ", tostring(DeviceDetail.operatingSystem)) | take %(t)d),
(SigninLogs | where TimeGenerated > ago(W) | where UserPrincipalName =~ A | where tostring(RiskLevelDuringSignIn) in ("low","medium","high")
 | summarize Cnt=count() by Leg="RISKY_SIGNIN", Key=strcat(tostring(RiskLevelDuringSignIn), " | ", tostring(RiskEventTypes_V2)) | take %(t)d),
(AuditLogs | where TimeGenerated > ago(W) | where tostring(TargetResources) has A
 | summarize Cnt=count() by Leg="AUDIT_CHANGE", Key=strcat(OperationName, " | ", tostring(InitiatedBy.user.userPrincipalName)) | take %(t)d)
""" % {"v": v, "t": TAKE}


def kql_ip(v):
    return """let W = 7d;
let I = "%(v)s";
union isfuzzy=true
(SigninLogs | where TimeGenerated > ago(W) | where IPAddress == I
 | summarize Cnt=count() by Leg="SIGNIN_BY_ACCOUNT", Key=strcat(UserPrincipalName, " | ", iff(ResultType=="0","SUCCESS","FAIL")) | take %(t)d),
(SigninLogs | where TimeGenerated > ago(30d) | where IPAddress == I
 | summarize D=dcount(UserPrincipalName) | project Leg="EGRESS_DCOUNT", Key=strcat("distinct accounts 30d: ", tostring(D)), Cnt=D),
(CommonSecurityLog | where TimeGenerated > ago(W) | where SourceIP == I or DestinationIP == I
 | summarize Cnt=count() by Leg="FIREWALL", Key=strcat(DeviceVendor, " | ", DeviceAction, " | ", tostring(DestinationPort)) | take %(t)d),
(DeviceNetworkEvents | where TimeGenerated > ago(W) | where RemoteIP == I
 | summarize Cnt=count() by Leg="EDR_NETWORK", Key=strcat(DeviceName, " | ", InitiatingProcessFileName) | take %(t)d)
""" % {"v": v, "t": TAKE}


def kql_host(v, t0):
    return """let T = datetime(%(t0)s);
let H = "%(v)s";
union isfuzzy=true
(DeviceLogonEvents | where TimeGenerated between (T - 1h .. T + 1h) | where DeviceName has H
 | summarize Cnt=count() by Leg="EDR_LOGON", Key=strcat(AccountName, " | ", LogonType, " | ", ActionType) | take %(t)d),
(DeviceProcessEvents | where TimeGenerated between (T - 1h .. T + 1h) | where DeviceName has H
 | summarize Cnt=count() by Leg="EDR_PROCESS", Key=strcat(FileName, " <- ", InitiatingProcessFileName) | take %(t)d),
(SecurityEvent | where TimeGenerated between (T - 1h .. T + 1h) | where Computer has H | where EventID in (4624, 4625, 4688)
 | summarize Cnt=count() by Leg="WINSEC", Key=strcat(tostring(EventID), " | ", Account) | take %(t)d)
""" % {"v": v, "t0": t0, "t": TAKE}


def kql_hash(v):
    return """let W = 7d;
let S = "%(v)s";
union isfuzzy=true
(DeviceFileEvents | where TimeGenerated > ago(W) | where SHA256 == S or SHA1 == S or MD5 == S
 | summarize Cnt=count() by Leg="EDR_FILE", Key=strcat(DeviceName, " | ", ActionType, " | ", FolderPath) | take %(t)d),
(DeviceProcessEvents | where TimeGenerated > ago(W) | where SHA256 == S or SHA1 == S or MD5 == S
 | summarize Cnt=count() by Leg="EDR_EXEC", Key=strcat(DeviceName, " | ", FolderPath) | take %(t)d),
(DeviceFileEvents | where TimeGenerated > ago(W) | where SHA256 == S or SHA1 == S or MD5 == S
 | summarize D=dcount(DeviceName) | project Leg="HOST_SPREAD", Key=strcat("distinct hosts 7d: ", tostring(D)), Cnt=D)
""" % {"v": v, "t": TAKE}


def kql_url(v):
    return """let W = 7d;
let U = "%(v)s";
union isfuzzy=true
(DeviceNetworkEvents | where TimeGenerated > ago(W) | where RemoteUrl has U
 | summarize Cnt=count() by Leg="EDR_URL", Key=strcat(DeviceName, " | ", InitiatingProcessFileName) | take %(t)d),
(EmailUrlInfo | where TimeGenerated > ago(W) | where Url has U
 | join kind=inner (EmailEvents | where TimeGenerated > ago(W)) on NetworkMessageId
 | summarize Cnt=count() by Leg="EMAIL_URL", Key=strcat(RecipientEmailAddress, " | ", Subject) | take %(t)d)
""" % {"v": v, "t": TAKE}


def kql_related(values):
    arr = json.dumps([str(v) for v in values][:20])
    return """let W = 30d;
let E = dynamic(%(e)s);
union isfuzzy=true
(SecurityAlert | where TimeGenerated > ago(W) | where tostring(Entities) has_any (E)
 | summarize Cnt=count() by Leg="RELATED_ALERTS", Key=strcat(AlertName, " | ", AlertSeverity) | take %(t)d),
(SecurityIncident | where TimeGenerated > ago(W) | where tostring(AdditionalData) has_any (E) or Title has_any (E)
 | summarize Cnt=count() by Leg="RELATED_INCIDENTS", Key=strcat(Title, " | ", Status) | take %(t)d)
""" % {"e": arr, "t": TAKE}


# ---------- RUNNER ----------

def run_query(query, instance, label, errors):
    """ONE QUERY. NEVER RAISES. A FAILED LEG IS RECORDED AND THE PACK CARRIES ON."""
    try:
        res = demisto.executeCommand("azure-log-analytics-execute-query",
                                     {"query": query, "using": instance})
        if isError(res[0]):
            errors.append({"Query": label, "Message": get_error(res)[:200]})
            return []
        ctx = res[0].get("EntryContext") or {}
        rows = []
        for k, v in ctx.items():
            if "AzureLogAnalytics" in k and isinstance(v, list):
                rows = v
                break
            if isinstance(v, dict) and isinstance(v.get("Query"), list):
                rows = v["Query"]
                break
        return rows or []
    except Exception as e:
        errors.append({"Query": label, "Message": str(e)[:200]})
        return []


def distil(rows):
    """GROUP THE UNION OUTPUT BY LEG, KEEP THE TOP N BY COUNT."""
    legs = {}
    for r in rows:
        if not isinstance(r, dict):
            continue
        leg = str(r.get("Leg") or r.get("leg") or "RESULT")
        key = str(r.get("Key") or r.get("key") or "")[:MAX_CELL]
        try:
            cnt = int(r.get("Cnt") or r.get("cnt") or 1)
        except Exception:
            cnt = 1
        legs.setdefault(leg, []).append({"Key": key, "Count": cnt})
    out = []
    for leg, items in legs.items():
        items.sort(key=lambda x: -x["Count"])
        out.append({"Name": leg,
                    "RowCount": sum(i["Count"] for i in items),
                    "Top": items[:MAX_ROWS]})
    return out


def count_leg(entity_blocks, name):
    n = 0
    for e in entity_blocks:
        for q in e["Queries"]:
            if q["Name"] == name:
                n += q["RowCount"]
    return n


def main():
    args = demisto.args()
    depth = (args.get("depth") or "light").lower()
    instance = args.get("la_instance") or ""
    alert_time = (args.get("alert_time") or "").strip() or "now()"
    try:
        cap = int(args.get("max_entities") or 8)
    except Exception:
        cap = 8

    if alert_time != "now()":
        alert_time = '"%s"' % alert_time.replace('"', "")

    pairs = normalise(args.get("entities"))[:cap]
    errors = []
    blocks = []
    raw = []

    # RULE RE-RUN COMES IN FROM THE PLAYBOOK, WE DO NOT RE-EXECUTE IT
    rule_rows = args.get("rule_results")
    if isinstance(rule_rows, str):
        try:
            rule_rows = json.loads(rule_rows)
        except Exception:
            rule_rows = []
    rule_rows = rule_rows if isinstance(rule_rows, list) else ([rule_rows] if rule_rows else [])
    if rule_rows:
        raw.append({"Leg": "RULE_RERUN", "Rows": rule_rows[:TAKE]})

    # ALWAYS, BOTH DEPTHS: RELATED ALERTS AND INCIDENTS FOR THESE ENTITIES
    if pairs:
        rows = run_query(kql_related([v for _, v in pairs]), instance, "RELATED", errors)
        raw.append({"Leg": "RELATED", "Rows": rows[:TAKE]})
        blocks.append({"Value": "ALL_ENTITIES", "Type": "Shared", "Queries": distil(rows)})

    # FULL DEPTH ONLY: ONE COMPOSITE QUERY PER ENTITY
    if depth == "full":
        for etype, value in pairs:
            safe = str(value).replace('"', "").replace("\\", "")
            if etype == "Account":
                q = kql_account(safe)
            elif etype == "IP":
                q = kql_ip(safe)
            elif etype == "Host":
                q = kql_host(safe, alert_time)
            elif etype == "FileHash":
                q = kql_hash(safe)
            elif etype in ("URL", "Domain"):
                q = kql_url(safe)
            else:
                continue
            rows = run_query(q, instance, "%s:%s" % (etype, safe), errors)
            raw.append({"Leg": "%s:%s" % (etype, safe), "Rows": rows[:TAKE]})
            blocks.append({"Value": safe, "Type": etype, "Queries": distil(rows)})

    # SUMMARY COUNTERS. THESE ARE WHAT THE AI PROMPT AND THE OVERVIEW CARD READ.
    egress = "UNKNOWN"
    for b in blocks:
        for q in b["Queries"]:
            if q["Name"] == "EGRESS_DCOUNT" and q["Top"]:
                egress = "LIKELY_CORPORATE_EGRESS" if q["Top"][0]["Count"] >= EGRESS_ACCOUNTS else "NARROW_USE"

    summary = {
        "Depth": depth,
        "EntitiesInvestigated": len(pairs),
        "FailedSignIns": count_leg(blocks, "SIGNIN_FAIL"),
        "SuccessfulSignIns": max(count_leg(blocks, "SIGNIN") - count_leg(blocks, "SIGNIN_FAIL"), 0),
        "DistinctIPs": len([1 for t, _ in pairs if t == "IP"]),
        "NewCountries": count_leg(blocks, "NEW_COUNTRY"),
        "NewDevices": count_leg(blocks, "NEW_DEVICE"),
        "RiskySignIns": count_leg(blocks, "RISKY_SIGNIN"),
        "AuditChanges": count_leg(blocks, "AUDIT_CHANGE"),
        "HostSpread": count_leg(blocks, "HOST_SPREAD"),
        "RelatedAlerts30d": count_leg(blocks, "RELATED_ALERTS"),
        "RelatedIncidents30d": count_leg(blocks, "RELATED_INCIDENTS"),
        "EgressHeuristic": egress,
        "RuleRerunRows": len(rule_rows),
        "QueriesFailed": len(errors),
    }

    investigation = {"Depth": depth, "Summary": summary, "Entities": blocks, "Errors": errors}

    md = tableToMarkdown("Investigation summary (%s depth)" % depth, [summary])
    if errors:
        md += "\n" + tableToMarkdown("Checks that did not run", errors)

    return_results(CommandResults(
        readable_output=md,
        outputs_prefix="Investigation",
        outputs_key_field="",
        outputs=investigation,
        raw_response=investigation,
    ))
    # RAW GOES OUT SEPARATELY SO THE PLAYBOOK CAN RENDER IT AND THEN DELETE IT
    demisto.setContext("InvestigationRaw", raw)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
