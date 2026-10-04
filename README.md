# AppleOS_Feed

Builds an email-ready summary of the current Apple OS patch status for **macOS, iOS and iPadOS**, using data from [SOFA](https://sofa.macadmins.io) (Simple Organized Feed for Apple Software Updates).

## What it produces

An Outlook-friendly HTML email covering:

- **Every supported release train** – a train counts as supported if Apple shipped an update for it in the last 365 days
- For each train: latest version, build, release date, number of CVEs fixed, and **actively exploited CVEs**, each linked to its record on [cve.org](https://www.cve.org)
- A table of **all Apple OS releases from the last 30 days**
- A headline banner that calls out any actively exploited CVEs

Version numbers link to Apple's security notes for that release.

## How it works

1. A GitHub Actions workflow runs `scripts/sofa_apple_patch_email.py`.
2. The script pulls the latest macOS and iOS/iPadOS data from SOFA, adds older iOS/iPadOS trains that SOFA doesn't track from [endoflife.date](https://endoflife.date/ios), and builds the email.
3. The workflow commits the result to `latest/`:
   - `latest/apple_patch_email.html` – the email body
   - `latest/subject.txt` – the subject line

Each run is a commit, so the repo history keeps a dated copy of every report.

## Running it

**From GitHub:** go to **Actions → Apple patch status email → Run workflow**.

**Locally** (Python 3, standard library only):

```bash
python3 scripts/sofa_apple_patch_email.py
```

Options:

| Flag | Default | Description |
| --- | --- | --- |
| `--days` | 30 | Window for the "recent releases" table |
| `--support-days` | 365 | How recently a train must have been updated to count as supported |
| `--all` | off | Include every train in the feed, including unsupported ones |
| `--out` | `.` | Output folder |

A local run writes `.html`, `.txt` and `.eml` versions of the email.

## Sending the email

Open `latest/apple_patch_email.html` in a browser, copy it, and paste it into a new email. The layout uses inline styles and tables, so it keeps its formatting in Outlook.

The raw file URLs can also be fetched by an automation tool, such as a scheduled Power Automate flow, to send the email automatically.

## Scheduling (optional)

The workflow is manual-only. To run it monthly, add a schedule under `on:` in `.github/workflows/apple-patch-email.yml`:

```yaml
on:
  workflow_dispatch: {}
  schedule:
    - cron: "0 13 2 * *"   # 13:00 UTC on the 2nd of each month
```

## Notes

- Apple does not publish end-of-support dates. "Supported" here is based on Apple's actual release activity, not on any
