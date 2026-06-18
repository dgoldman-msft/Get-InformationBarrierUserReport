# How to Use the Information Barrier Report Dashboard

## Prerequisites

- Python 3.10 or later
- PowerShell 7.1 or later with the `ExchangeOnlineManagement` module
- An M365 account with Information Barriers Administrator, Compliance Administrator,
  or Global Administrator role

## Setup

```powershell
cd C:\GitHub\Get-InformationBarrierUserReport\dashboard
pip install -r requirements.txt
streamlit run app.py
```

The dashboard opens at `http://localhost:8501` in your default browser.

## Sidebar settings

| Setting | Description |
|---------|-------------|
| **Module path** | Path to `Get-InformationBarrierUserReport.psd1` |
| **Log directory** | Where CSV and log files are saved |
| **Auth method** | Interactive, Device code, Credential, Service Principal, Managed Identity |
| **Organization** | Required for non-interactive auth (e.g. `contoso.onmicrosoft.com`) |
| **Enumerate users** | Also list individual UPNs in blocked/allowed segments |
| **Max users per segment** | Cap on enumerated users (0 = unlimited) |
| **Stay connected** | Keep IPPS session alive after the run |

Click **Save settings** to persist across restarts.

## Run Report tab

Choose an input mode:

- **UPN lookup** — enter one or more UPNs (one per line or comma-separated)
- **Segment enumeration** — enter a segment name to enumerate all users in it
- **List all policies** — print the full IB policy matrix with no per-user lookup

Then click **Run**.

## Results tab

Shows KPI cards, a status distribution pie chart, an account-type bar chart,
and a filterable/downloadable table of all records.

## Raw Log tab

Shows the raw stdout and stderr from the PowerShell run for troubleshooting.
