# Cloudflare SSL Global Checker

A PowerShell script that checks the SSL/TLS edge certificates on **every zone** in one or more Cloudflare accounts. You get a single answer per account: either every certificate is healthy, or a table of exactly what needs attention.

```text
=== My Account ===
Checking 48 zones...
Successful: All SSLs are working as intended. (48 zones checked)
```

## What it checks

For every zone the API token can see, it flags:

| Check | Flagged when |
|---|---|
| Zone status | The zone is anything other than `active` (e.g. `pending`, `moved`) |
| Active certificate | The zone has no active certificate pack |
| Certificate pack status | A pack is in any status other than `active` or `backup_issued` (e.g. `pending_validation`, `validation_timed_out`) |
| Expiry | An active certificate has expired, or expires within 14 days (configurable) |

That last check matters because a certificate pack can still show as `active` while repeated Domain Control Validation (DCV) failures stop it renewing.

## Features

- **Multiple accounts.** Save as many Cloudflare accounts as you like, each with its own token. Run one, several (`1,3`) or all of them from a menu.
- **Tokens stored encrypted.** Tokens are encrypted with Windows DPAPI in `%APPDATA%\cf-ssl-audit\accounts.json`. Only your Windows user on your PC can decrypt them.
- **Read-only.** The script only ever reads from the Cloudflare API. It never changes anything.
- **Validates tokens before saving.** A token that Cloudflare rejects is never stored.
- **Handles API problems.** Rate limits, server errors and network failures are retried automatically. A failure on one zone doesn't stop the rest of the audit.
- Works on **Windows PowerShell 5.1** (built into Windows) and **PowerShell 7+**.

---

## 1. Create a Cloudflare API token

1. In the Cloudflare dashboard, type **"api"** into the quick search box, then click **"API tokens"**.
2. Click **"Create Token"**.
3. Next to **Create Custom Token**, click **"Get started"**.
4. **Token name:** enter any name you like, e.g. `Global SSL Checker`.
5. **Permissions**, first row:
   1. Change the first dropdown from **"Account"** to **"Zone"**.
   2. In the next dropdown, select **"SSL and Certificates"**.
   3. In the last dropdown, choose **"Read"**.
6. **Permissions**, second row: click **"+ Add more"**, then choose **"Zone"**, **"Zone"** and **"Read"**. The script needs this to list your zones.
7. **Zone Resources:**
   1. Set the first dropdown to **"Includes"**.
   2. Set the second dropdown to **"All zones"**.
8. **Security** (optional, but recommended):
   - **If you have a static IP address**, go to **Client IP Address Filtering**, set the Operator to **"Is in"** and click **"Use my IP"**. The token then only works from your connection.
   - **If you don't have a static IP address**, use the **TTL** setting to give the token an end date. Unless you run the audit daily, it's better not to leave a token valid indefinitely; create a new short-lived one when you need it.
9. Click **"Continue to summary"**, then **"Create Token"**.
10. Copy the token. Cloudflare only shows it once. The script asks for it the first time you run it.

> [!TIP]
> If you manage several Cloudflare accounts, create one token per account and add each one to the script under its own name.

## 2. Run the script

Download `cf-ssl-audit.ps1`, open PowerShell in the folder you saved it to, and choose one of the options below.

### Option A: run it without changing any settings

Windows blocks scripts by default. This command bypasses that for this one run only, and doesn't need administrator rights:

```powershell
powershell -ExecutionPolicy Bypass -File .\cf-ssl-audit.ps1
```

Use this same command every time you run the audit.

### Option B: allow it once, then run it directly

Allow local scripts for your Windows user (no administrator rights needed), and unblock the downloaded file:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

```powershell
Unblock-File .\cf-ssl-audit.ps1
```

From then on, run it with:

```powershell
.\cf-ssl-audit.ps1
```

### Using the menu

The first time you run it, the script asks for an account name and API token. After that, it shows a menu:

```text
Saved Cloudflare accounts:
  1) My Account
  2) Client Account
  A) Run ALL accounts
  N) Add a new account
  R) Remove an account
  Q) Quit
Choose (a number, or several like 1,3):
```

To change how early expiring certificates are flagged (the default is 14 days):

```powershell
.\cf-ssl-audit.ps1 -ExpiryWarningDays 30
```

## Example output when there are problems

```text
=== Client Account ===
Checking 12 zones...
2 problem(s) found across 12 zones:

Zone         Issue                            Detail
----         -----                            ------
example.com  Certificate expires in 6 day(s)  google / universal / expires 2026-10-15 12:00 UTC / a1b2...
example.net  Pack status 'pending_validation' google / universal / txt / c3d4...
```

If the token has been rolled, has expired or has lost its permissions, the script says so. Remove the account from the menu (**R**) and add it again (**N**) with a new token.

## Security notes

- Tokens are never written to disk in plain text and are never printed.
- The saved tokens can't be decrypted from another Windows user account or another PC. If you move to a new machine, add the accounts again.
- When you remove an account, the script deletes its saved token. Remember to also delete or roll the token in Cloudflare if you no longer need it.
