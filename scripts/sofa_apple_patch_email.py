#!/usr/bin/env python3
"""
SOFA Apple patching view -> email-ready HTML + plain text.

Pulls the macOS and iOS/iPadOS feeds from SOFA (sofa.macadmins.io) and builds an
Outlook-safe HTML email (inline styles, table layout) plus a plain-text version.

Usage:
    python3 sofa_apple_patch_email.py                 # writes files to ./
    python3 sofa_apple_patch_email.py --days 30       # "recent releases" window
    python3 sofa_apple_patch_email.py --support-days 365  # supported = Apple shipped
                                                          # an update in this window
    python3 sofa_apple_patch_email.py --all           # every train in the feed
    python3 sofa_apple_patch_email.py --out /path     # output folder

Outputs:
    apple_patch_email.html  -> open in browser, Ctrl+A, Ctrl+C, paste into Outlook
    apple_patch_email.txt   -> plain-text fallback / Teams post
    apple_patch_email.eml   -> double-click to open as a draft in Outlook/Mail
Standard library only, so it runs on a stock Mac or Windows Python.
"""
import argparse
import html
import json
import urllib.request
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path

FEEDS = {
    "macos": [
        "https://sofafeed.macadmins.io/v1/macos_data_feed.json",
        "https://raw.githubusercontent.com/macadmins/sofa/main/v1/macos_data_feed.json",
    ],
    "ios": [
        "https://sofafeed.macadmins.io/v1/ios_data_feed.json",
        "https://raw.githubusercontent.com/macadmins/sofa/main/v1/ios_data_feed.json",
    ],
}
# endoflife.date fills in iOS/iPadOS trains SOFA doesn't track (e.g. 15, 16)
EOL_URL = "https://endoflife.date/api/ios.json"
APPLE_SEC = "https://support.apple.com/en-us/100100"  # Apple security releases index
UA = {"User-Agent": "sofa-patch-email/1.0"}  # SOFA asks clients to send a UA

RED, AMBER, GREEN, GREY = "#B42318", "#B54708", "#067647", "#475467"
FONT = "font-family:Segoe UI,Arial,sans-serif;"
NOW = datetime.now(timezone.utc)


def fetch(kind):
    last_err = None
    for url in FEEDS[kind]:
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.load(r)
        except Exception as e:  # try the mirror
            last_err = e
    raise SystemExit(f"Could not fetch {kind} feed: {last_err}")


def cve_link(cve):
    """Link a CVE ID to its official record on cve.org (the MITRE-run CVE Program site)."""
    c = html.escape(cve)
    return (f'<a href="https://www.cve.org/CVERecord?id={c}" '
            f'style="color:{RED};text-decoration:underline;">{c}</a>')


def fetch_eol():
    try:
        req = urllib.request.Request(EOL_URL, headers=UA)
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)
    except Exception as e:
        print(f"Warning: endoflife.date unavailable ({e}); showing SOFA trains only")
        return None


def vtuple(v):
    return tuple(int(x) for x in str(v).split(".") if x.isdigit())


def merge_eol(rows, eol, support_days=365, show_all=False):
    """Add trains SOFA doesn't track and flag where SOFA looks behind."""
    if not eol:
        return rows
    by_major = {r["major"].split()[-1]: r for r in rows}
    for c in eol:
        latest, date = c.get("latest"), c.get("latestReleaseDate")
        if not latest or not date:
            continue
        major = str(c["cycle"]).split(".")[0]
        released = f"{date}T00:00:00Z"
        if major in by_major:
            r = by_major[major]
            if vtuple(latest) > vtuple(r["version"]):
                # SOFA is behind: show the newer release; its CVE detail isn't in SOFA
                r.update(version=latest, build="—", released=released,
                         cves=None, exploited=None, link=APPLE_SEC)
            continue
        e = c.get("eol")
        ended = e is True or (isinstance(e, str) and dt(f"{e}T00:00:00Z") < NOW)
        if not show_all and (ended or days_ago(released) > support_days):
            continue
        rows.append({
            "major": major, "version": latest, "build": "—", "released": released,
            "cves": None, "exploited": None, "link": APPLE_SEC,
            "stale": days_ago(released) > 365, "expires_soon": False, "expiry": None,
        })
    rows.sort(key=lambda r: vtuple(r["major"].split()[-1]), reverse=True)
    return rows


def dt(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def days_ago(s):
    return (NOW - dt(s)).days


def fmt_date(s):
    return dt(s).strftime("%b %d, %Y").replace(" 0", " ")


def supported(feed, support_days=365, show_all=False):
    """Apple doesn't publish an end-of-support date, so treat a train as supported
    if Apple has shipped an update for it within support_days."""
    if show_all:
        return feed["OSVersions"]
    return [o for o in feed["OSVersions"] if days_ago(o["Latest"]["ReleaseDate"]) <= support_days]


def latest_rows(versions):
    rows = []
    for idx, o in enumerate(versions):
        L = o["Latest"]
        exp = L.get("ExpirationDate")
        exploited = L.get("ActivelyExploitedCVEs", [])
        rows.append({
            "major": o["OSVersion"],
            "version": L["ProductVersion"],
            "build": L["Build"],
            "released": L["ReleaseDate"],
            "cves": L.get("UniqueCVEsCount", 0),
            "exploited": exploited,
            "link": L.get("SecurityInfo", ""),
            "stale": days_ago(L["ReleaseDate"]) > 365,
            "expires_soon": bool(exp) and 0 <= (dt(exp) - NOW).days <= 60,
            "expiry": exp,
        })
    return rows


def recent_releases(versions, window):
    out = []
    for o in versions:
        for sr in o.get("SecurityReleases", []):
            if days_ago(sr["ReleaseDate"]) <= window:
                out.append(sr)
    return sorted(out, key=lambda s: s["ReleaseDate"], reverse=True)


# ---------- HTML ----------
def th(text):
    return (f'<th style="{FONT}font-size:12px;text-align:left;padding:6px 8px;'
            f'background:#F2F4F7;color:#344054;border-bottom:1px solid #D0D5DD;">{text}</th>')


def td(text, color="#101828", bold=False):
    w = "600" if bold else "400"
    return (f'<td style="{FONT}font-size:13px;padding:6px 8px;color:{color};'
            f'font-weight:{w};border-bottom:1px solid #EAECF0;vertical-align:top;">{text}</td>')


def latest_table(title, rows, os_prefix):
    h = [f'<h3 style="{FONT}font-size:15px;color:#101828;margin:20px 0 6px;">{title}</h3>',
         '<table cellpadding="0" cellspacing="0" border="0" width="100%" '
         'style="border-collapse:collapse;border:1px solid #D0D5DD;">',
         "<tr>" + "".join(th(x) for x in
                          ["Release", "Latest", "Build", "Released", "CVEs", "Exploited CVEs"]) + "</tr>"]
    for r in rows:
        if r["exploited"] is None:
            exploited = "—"
        else:
            exploited = ("<br>".join(cve_link(c) for c in r["exploited"]) if r["exploited"] else "None")
        name = f'{os_prefix} {html.escape(r["major"])}'
        if r["stale"]:
            name += f'<br><span style="color:{RED};font-size:11px;">No update in over a year</span>'
        ver = f'<a href="{r["link"]}" style="color:#175CD3;">{r["version"]}</a>' if r["link"] else r["version"]
        h.append("<tr>" + td(name) + td(ver, bold=True) + td(r["build"], GREY)
                 + td(f'{fmt_date(r["released"])}<br><span style="color:{GREY};font-size:11px;">'
                      f'{days_ago(r["released"])} days ago</span>')
                 + td("—" if r["cves"] is None else str(r["cves"])) + td(exploited, RED if r["exploited"] else GREY, bold=bool(r["exploited"]))
                 + "</tr>")
    h.append("</table>")
    return "\n".join(h)


def recent_table(releases, window):
    if not releases:
        return (f'<p style="{FONT}font-size:13px;color:{GREY};">No Apple OS releases in the last '
                f'{window} days.</p>')
    h = [f'<h3 style="{FONT}font-size:15px;color:#101828;margin:20px 0 6px;">'
         f'All releases in the last {window} days</h3>',
         '<table cellpadding="0" cellspacing="0" border="0" width="100%" '
         'style="border-collapse:collapse;border:1px solid #D0D5DD;">',
         "<tr>" + "".join(th(x) for x in ["Update", "Released", "CVEs", "Exploited CVEs"]) + "</tr>"]
    for s in releases:
        ex = s.get("ActivelyExploitedCVEs", [])
        name = html.escape(s["UpdateName"])
        if s.get("SecurityInfo"):
            name = f'<a href="{s["SecurityInfo"]}" style="color:#175CD3;">{name}</a>'
        h.append("<tr>" + td(name) + td(fmt_date(s["ReleaseDate"]))
                 + td(str(s.get("UniqueCVEsCount", 0)))
                 + td("<br>".join(cve_link(c) for c in ex) if ex else "None", RED if ex else GREY, bold=bool(ex)) + "</tr>")
    h.append("</table>")
    return "\n".join(h)


def build(args):
    mac, ios = fetch("macos"), fetch("ios")
    mac_v = supported(mac, args.support_days, args.all)
    ios_v = supported(ios, args.support_days, args.all)
    mac_rows = latest_rows(mac_v)
    ios_rows = merge_eol(latest_rows(ios_v), fetch_eol(), args.support_days, args.all)
    recent = recent_releases(mac_v, args.days) + recent_releases(ios_v, args.days)
    recent.sort(key=lambda s: s["ReleaseDate"], reverse=True)

    exploited = sorted({c for r in mac_rows + ios_rows for c in (r["exploited"] or [])})
    today = datetime.now().astimezone().strftime("%b %d, %Y").replace(" 0", " ")

    if exploited:
        headline = (f'{len(exploited)} actively exploited CVE(s) fixed in current Apple releases: '
                    f'{", ".join(cve_link(c) for c in exploited)}. See the Exploited CVEs column below for the affected releases.')
        headline_text = (f'{len(exploited)} actively exploited CVE(s) fixed in current Apple releases: '
                         f'{", ".join(exploited)}.')
        hcolor, hbg = RED, "#FEF3F2"
    else:
        headline = "No actively exploited vulnerabilities in the current Apple releases."
        headline_text = headline
        hcolor, hbg = GREEN, "#ECFDF3"

    subject = f"Apple OS patch status — {today}" + (" — ACTION: actively exploited CVEs" if exploited else "")

    body = f"""<div style="{FONT}max-width:820px;">
<p style="{FONT}font-size:14px;color:#101828;">Team,</p>
<p style="{FONT}font-size:14px;color:#101828;">Below is the current Apple patch picture for macOS, iOS and iPadOS, as of {today}.</p>
<table cellpadding="0" cellspacing="0" border="0" width="100%"><tr>
<td style="{FONT}font-size:14px;padding:10px 12px;background:{hbg};color:{hcolor};border-left:4px solid {hcolor};font-weight:600;">{headline}</td>
</tr></table>
{latest_table("macOS — all supported release trains", mac_rows, "macOS")}
{latest_table("iOS / iPadOS — all supported release trains", ios_rows, "iOS/iPadOS")}
{recent_table(recent, args.days)}
<p style="{FONT}font-size:11px;color:{GREY};margin-top:16px;">Source: SOFA by Mac Admins Open Source (sofa.macadmins.io). Version numbers link to Apple's security notes. CVE counts are unique CVEs listed for each release. "Supported" means Apple shipped an update for that train in the last {args.support_days} days; Apple does not publish formal end-of-support dates.</p>
</div>"""

    html_doc = (f'<!DOCTYPE html><html><head><meta charset="utf-8"><title>{html.escape(subject)}</title>'
                f'</head><body style="margin:16px;">{body}</body></html>')

    # ---------- plain text ----------
    t = [subject, "", headline_text, ""]
    for title, rows, pre in [("macOS", mac_rows, "macOS"), ("iOS / iPadOS", ios_rows, "iOS/iPadOS")]:
        t.append(f"{title}")
        for r in rows:
            t.append(f"  {pre} {r['major']}: {r['version']} ({r['build']}) "
                     f"released {fmt_date(r['released'])} — "
                     + (f"{r['cves']} CVEs — exploited CVEs: {', '.join(r['exploited']) or 'none'}"
                        if r["exploited"] is not None else "CVE detail: see Apple security notes")
                     )
        t.append("")
    t.append(f"Releases in the last {args.days} days:")
    for s in recent:
        t.append(f"  {fmt_date(s['ReleaseDate'])}  {s['UpdateName']}  ({s.get('UniqueCVEsCount', 0)} CVEs)")
    t += ["", "Source: https://sofa.macadmins.io"]
    text = "\n".join(t)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "apple_patch_email.html").write_text(html_doc, encoding="utf-8")
    (out / "apple_patch_email.txt").write_text(text, encoding="utf-8")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["X-Unsent"] = "1"  # Outlook opens .eml as an editable draft
    msg.set_content(text)
    msg.add_alternative(html_doc, subtype="html")
    (out / "apple_patch_email.eml").write_bytes(bytes(msg))

    print(subject)
    print(f"Wrote {out/'apple_patch_email.html'}, .txt and .eml")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--days", type=int, default=30)
    p.add_argument("--support-days", type=int, default=365)
    p.add_argument("--all", action="store_true", help="include every train in the feed")
    p.add_argument("--out", default=".")
    build(p.parse_args())
