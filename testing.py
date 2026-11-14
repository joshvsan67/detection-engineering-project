import base64
import gzip
from urllib.parse import quote

email = """{{ $.request.requestedByUserPrincipalName }}"""
fname = """{{ $.request.applicationDetail.fileName }}"""
fhash = """{{ $.request.applicationDetail.fileHash }}"""
tenant = """{{ $.pick_a_skyline_tenant_id.output }}"""

FENCE = "`" * 3
BLANKS = {"<nil>", "null", "none", "<no value>", ""}


def clean(v):
    v = (v or "").strip()
    return "" if v.lower() in BLANKS else v


def esc(s):
    return s.replace("\\", "\\\\").replace('"', '\\"')


def make_link(q):
    if not tenant:
        return ""
    packed = base64.b64encode(gzip.compress(q.encode())).decode()
    return (
        "https://security.microsoft.com/v2/advanced-hunting"
        f"?tid={quote(tenant, safe='')}&query={quote(packed, safe='')}"
    )


try:
    email = clean(email)
    fname = clean(fname)
    tenant = clean(tenant)
    fhash = clean(fhash).upper()
    user = email.split("@")[0] if email else ""
    if len(fhash) != 64 or any(c not in "0123456789ABCDEF" for c in fhash):
        fhash = ""

    hunts = []

    if fhash:
        hunts.append((
            "Download source and creation date",
            "",
            f"""DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 =~ "{esc(fhash)}"
| project Timestamp, DeviceName, ActionType, FolderPath,
    FileOriginUrl, FileOriginReferrerUrl,
    InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp asc
| take 200""",
        ))
        hunts.append((
            "Devices with this hash",
            "",
            f"""union DeviceFileEvents, DeviceProcessEvents
| where Timestamp > ago(30d)
| where SHA256 =~ "{esc(fhash)}"
| summarize Devices = dcount(DeviceId),
    DeviceList = make_set(DeviceName, 100),
    FirstSeen = min(Timestamp)""",
        ))

    elif fname and user:
        hunts.append((
            "Download source by file name and user",
            "_No usable file hash on this request, so this search is broader and may include unrelated files._",
            f"""DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName =~ "{esc(fname)}"
    and InitiatingProcessAccountName =~ "{esc(user)}"
| project Timestamp, DeviceName, ActionType, FolderPath,
    FileOriginUrl, FileOriginReferrerUrl, SHA256
| order by Timestamp asc
| take 200""",
        ))

    if user:
        hunts.append((
            "Devices the user signed in to",
            "",
            f"""DeviceLogonEvents
| where Timestamp > ago(30d)
| where AccountName =~ "{esc(user)}"
| summarize LastLogon = max(Timestamp), Logons = count() by DeviceName
| top 10 by LastLogon desc""",
        ))

    lines = ["### Defender Hunting", "Searches cover the last 30 days.", ""]

    if not hunts:
        lines.append(
            "No lookup available. The request had no usable file hash, file name or user. "
            "Run the hunts manually in Defender Advanced Hunting."
        )
    else:
        for title, note, q in hunts:
            url = make_link(q)
            link_line = (
                f"[Open in Defender]({url})"
                if url
                else "_No tenant ID, so no link. Paste the query into Advanced Hunting._"
            )
            lines.append(f"#### {title}")
            if note:
                lines.append(note)
            lines += [link_line, "", f"{FENCE}\n{q}\n{FENCE}", ""]

    print("\n".join(lines))

except Exception as exc:
    print(
        "### Defender Hunting\n\n"
        "No lookup available. The hunting queries could not be built ("
        + str(exc)
        + "). Run the hunts manually in Defender Advanced Hunting."
    )
