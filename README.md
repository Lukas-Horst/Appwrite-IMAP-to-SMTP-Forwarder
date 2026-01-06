# Appwrite IMAP-to-SMTP Forwarder

A robust Appwrite Function designed to poll multiple external email accounts via IMAP (Inbox & Spam) and forward new messages to a specified target address using a **centralized SMTP relay** (e.g., Gmail, Brevo).

The function runs on a schedule (CRON), handles complex email parsing (HTML/Attachments), avoids Spam-Blocking via "Clean Headers", and includes a safety mechanism for old emails.

## Features

- **Multi-Account Support:** Polls multiple email accounts (IMAP) stored in an Appwrite Database.
- **Full Folder Scan:** Checks `INBOX` as well as common Spam/Junk folders to ensure no important mail is missed.
- **Centralized SMTP Relay:** Uses a single, verified SMTP account (like a dedicated Gmail or Brevo account) to forward emails. This solves "Spoofing" errors (Error 550) common with Yahoo/Gmail.
- **Smart Header Handling:**
  - **From:** Sets the name of the original sender but uses the Relay-Email as the technical sender to pass DMARC/SPF checks.
  - **Reply-To:** Sets the *original sender's* email, so hitting "Reply" works seamlessly.
- **24h Safety Guard:** Emails older than 24 hours are **not** forwarded (to prevent loops or massive backlog processing). Instead, a system alert is sent.
- **State Management:** Tracks `last_check` per account to prevent duplicates.

## Prerequisites

- An active **Appwrite** instance.
- Python 3.9+ runtime.
- **A Central Email Account for Sending:**
  - Recommendation: A dedicated **Gmail** account with *App Password* enabled.
  - Alternatively: Brevo, SendGrid, etc.

## Setup & Configuration

### 1. Database Setup

Create a Database and a Collection in Appwrite. Add the following attributes:

| Attribute Name | Type    | Required | Description                                                                 |
| :------------- | :------ | :------- | :-------------------------------------------------------------------------- |
| `Provider`     | String  | Yes      | The IMAP Hostname (e.g., `imap.mail.yahoo.com`).                            |
| `user_email`   | String  | Yes      | The email address of the account to check.                                  |
| `user_name`    | String  | No       | (Optional) User's name.                                                     |
| `password`     | String  | Yes      | The IMAP password (use **App Passwords** for Yahoo, Gmail, iCloud).         |
| `to_email`     | String  | Yes      | The destination email address where messages should be forwarded.           |
| `last_check`   | Integer | No       | Stores the UNIX timestamp of the last successful check. Default to `0`.     |

### 2. Environment Variables

Go to your Function settings in the Appwrite Console and add the following variables.

**Appwrite Config:**
| Variable           | Description                                      |
| :----------------- | :----------------------------------------------- |
| `APPWRITE_API_KEY` | API Key with `documents.read` and `documents.write` scopes. |
| `DATABASE_ID`      | ID of your database.                             |
| `COLLECTION_ID`    | ID of the collection containing the accounts.    |

**Central SMTP Config (The Relay):**
| Variable             | Description                                          | Example (Gmail)        |
| :------------------- | :--------------------------------------------------- | :--------------------- |
| `CENTRAL_SMTP_HOST`  | SMTP Host of your relay service.                     | `smtp.gmail.com`       |
| `CENTRAL_SMTP_PORT`  | SMTP Port (usually 465 for SSL).                     | `465`                  |
| `CENTRAL_SMTP_USER`  | The email address of the relay account.              | `my.relay@gmail.com`   |
| `CENTRAL_SMTP_PASS`  | The password (or App Password) for the relay.        | `xxxx xxxx xxxx xxxx`  |

### 3. Deployment

1. Add `main.py` and `requirements.txt` to your function.
2. Ensure `requirements.txt` contains:
   ```text
   appwrite