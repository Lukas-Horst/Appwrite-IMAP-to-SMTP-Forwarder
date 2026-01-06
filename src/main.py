import os
import time
import imaplib
import smtplib
import ssl
import email
import socket
import warnings

# Attempt to import the html module for escaping special characters.
# Includes a fallback in case the module is not available in the environment.
try:
    import html
except ImportError:
    html = None

# Suppress DeprecationWarnings to keep the Appwrite function logs clean.
warnings.filterwarnings("ignore", category=DeprecationWarning)

from email.header import decode_header
from email.utils import parsedate_to_datetime, formataddr, parseaddr
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

from appwrite.client import Client
from appwrite.services.databases import Databases

# Set a global timeout for socket connections to prevent the script from hanging indefinitely.
socket.setdefaulttimeout(10)


def clean_text(text, encoding):
    """
    Decodes email header text to a readable string.
    Handles various encodings (UTF-8, Latin-1) and fallback scenarios.
    """
    if isinstance(text, bytes):
        if encoding:
            try:
                return text.decode(encoding)
            except LookupError:
                return text.decode('utf-8', errors='replace')
            except UnicodeDecodeError:
                return text.decode('latin-1', errors='replace')
        else:
            return text.decode('utf-8', errors='replace')
    return str(text)


def escape_html(text):
    """
    Escapes HTML special characters to prevent rendering issues in email bodies.
    Uses the html module if available, otherwise uses a manual replacement fallback.
    """
    if html:
        return html.escape(str(text))
    else:
        return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def get_clean_sender_info(msg):
    """
    Extracts and parses the 'From' header from an email.
    Returns a tuple containing the real name and the email address.
    Example: ('John Doe', 'john@example.com')
    """
    raw_from = msg.get("From", "")
    if not raw_from: return "Unknown", ""

    try:
        # Decode the header which might be MIME encoded (e.g., =?UTF-8?B?...)
        decoded_fragments = decode_header(raw_from)
        decoded_from = ""
        for part, encoding in decoded_fragments:
            if isinstance(part, bytes):
                try:
                    decoded_from += part.decode(encoding or "utf-8", errors="ignore")
                except:
                    decoded_from += part.decode("latin-1", errors="ignore")
            else:
                decoded_from += str(part)
    except Exception:
        decoded_from = str(raw_from)

    # Parse the decoded string into name and email address
    real_name, clean_email = parseaddr(decoded_from)

    # If no name was found, use the email address as the name
    if not real_name: real_name = clean_email

    return real_name, clean_email


def get_email_content_and_attachments(msg):
    """
    Traverses the email structure to extract the body content and attachments.
    Prioritizes HTML content over plain text if available.
    """
    body = ""
    is_html = False
    attachments = []

    try:
        if msg.is_multipart():
            # Walk through all parts of the email
            for part in msg.walk():
                ctype = part.get_content_type()
                cdispo = str(part.get("Content-Disposition"))

                # Check if the part is an attachment
                if part.get_filename() or "attachment" in cdispo:
                    filename = part.get_filename()
                    if filename:
                        # Decode the filename
                        decoded_list = decode_header(filename)
                        filename_bytes, encoding = decoded_list[0]
                        if isinstance(filename_bytes, bytes):
                            filename = filename_bytes.decode(encoding or 'utf-8', errors='ignore')
                        else:
                            filename = str(filename_bytes)

                    file_data = part.get_payload(decode=True)
                    if file_data:
                        attachments.append({"filename": filename, "content": file_data,
                            "maintype": part.get_content_maintype(),
                            "subtype": part.get_content_subtype()})
                    continue

                # extract HTML body
                if ctype == "text/html" and not is_html:
                    payload = part.get_payload(decode=True)
                    if payload:
                        try:
                            body = payload.decode('utf-8', errors='replace')
                        except:
                            body = payload.decode('latin-1', errors='replace')
                        is_html = True

                # Extract plain text body (fallback)
                elif ctype == "text/plain" and not body and not is_html:
                    payload = part.get_payload(decode=True)
                    if payload:
                        try:
                            body = payload.decode('utf-8', errors='replace')
                        except:
                            body = payload.decode('latin-1', errors='replace')
        else:
            # Handle non-multipart emails
            payload = msg.get_payload(decode=True)
            ctype = msg.get_content_type()
            if payload:
                try:
                    body = payload.decode('utf-8', errors='replace')
                except:
                    body = payload.decode('latin-1', errors='replace')
                if ctype == "text/html": is_html = True

    except Exception as e:
        body = f"[Error parsing content: {str(e)}]"

    return body if body else "[No content]", is_html, attachments


def send_alert_central(to_email, original_subject, original_sender_name):
    """
    Sends a system alert email using the central SMTP relay.
    Used when an email cannot be forwarded (e.g., due to age limits).
    """
    smtp_host = os.environ.get("CENTRAL_SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.environ.get("CENTRAL_SMTP_PORT", 465))
    smtp_user = os.environ.get("CENTRAL_SMTP_USER")
    smtp_pass = os.environ.get("CENTRAL_SMTP_PASS")

    if not (smtp_user and smtp_pass): return False, "Missing Gmail Creds"

    msg = MIMEMultipart()
    msg["From"] = f"Mail Bot <{smtp_user}>"
    msg["To"] = to_email
    msg["Subject"] = f"⚠️ [ALERT] Failed: {original_subject}"

    safe_sender = escape_html(original_sender_name)
    html_body = f"<h2>Failed to forward</h2><p>Original Sender: {safe_sender}</p>"
    msg.attach(MIMEText(html_body, "html"))

    try:
        # Connect using SSL (Port 465)
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(smtp_host, smtp_port, context=context) as server:
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, to_email, msg.as_string())
        return True, None
    except Exception as e:
        return False, str(e)


def send_forward_central(to_email, original_subject, original_name, original_email, body, is_html,
                         atts):
    """
    Forwards the email content using the central Gmail SMTP relay.
    Constructs the email to look like it comes from the original sender
    by setting the Display Name and Reply-To headers appropriately.
    """
    smtp_host = os.environ.get("CENTRAL_SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.environ.get("CENTRAL_SMTP_PORT", 465))
    smtp_user = os.environ.get("CENTRAL_SMTP_USER")
    smtp_pass = os.environ.get("CENTRAL_SMTP_PASS")

    if not (smtp_user and smtp_pass): return False, "Missing Gmail Creds"

    msg = MIMEMultipart()

    # Set the 'From' header.
    # We use the original sender's NAME for display, but the relay's EMAIL address
    # to authenticate correctly with the SMTP server.
    display_name = f"{original_name}"
    msg["From"] = formataddr((display_name, smtp_user))

    msg["To"] = to_email

    # Use the original subject line exactly as is.
    msg["Subject"] = original_subject

    # Set 'Reply-To' to the original sender's email.
    # This ensures that hitting 'Reply' sends the mail to the correct person, not the relay.
    if original_email:
        msg["Reply-To"] = original_email

    # Attach the body content directly without adding extra header info blocks.
    if is_html:
        msg.attach(MIMEText(body, "html"))
    else:
        msg.attach(MIMEText(body, "plain"))

    # Process and attach files
    for att in atts:
        try:
            part = MIMEBase(att['maintype'], att['subtype'])
            part.set_payload(att['content'])
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", f"attachment; filename= {att['filename']}")
            msg.attach(part)
        except:
            pass

    try:
        # Establish a secure SSL connection to the SMTP server
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=60, context=context) as server:
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, to_email, msg.as_string())
        return True, None
    except Exception as e:
        return False, str(e)


def get_existing_folders(mail, context, user_email):
    """
    Connects to the IMAP server to list available folders.
    Filters for common names for inbox and spam folders to avoid
    selecting non-existent folders later.
    """
    folders_to_check = ["INBOX"]
    possible_spam = ["Spam", "Junk", "Bulk", "[Gmail]/Spam", "Junk E-mail"]
    try:
        status, response = mail.list()
        if status == "OK":
            all_folders_str = str(response)
            for spam_name in possible_spam:
                # Check if the spam folder name exists in the server response
                if f'"{spam_name}"' in all_folders_str or f' {spam_name}' in all_folders_str:
                    folders_to_check.append(spam_name)
    except:
        return ["INBOX"]

    # Remove duplicates
    return list(set(folders_to_check))


def process_single_account(doc, databases, current_timestamp, context):
    """
    Main logic for processing a single email account document from the database.
    Connects via IMAP, fetches recent emails, checks if they are new,
    and forwards them or sends an alert.
    """
    imap_host = doc.get("Provider")
    user_email = doc.get("user_email")
    password = doc.get("password")
    last_check = doc.get("last_check", 0)
    target_email = doc.get("to_email", "").strip()

    doc_id = doc["$id"]
    db_id = doc["$databaseId"]
    col_id = doc["$collectionId"]

    # Validate that all necessary credentials are present
    if not (imap_host and user_email and password and target_email):
        context.error(f"Skipping {doc_id}: Missing IMAP credentials.")
        return

    context.log(f"--- Processing: {user_email} ---")

    mail = None
    ONE_DAY = 86400  # 24 hours in seconds
    max_ts = last_check

    try:
        # Connect to IMAP server
        mail = imaplib.IMAP4_SSL(imap_host)
        mail.login(user_email, password)

        # Identify folders to scan (Inbox + detected Spam folders)
        folders = get_existing_folders(mail, context, user_email)

        for folder in folders:
            try:
                # Select folder
                status, _ = mail.select(folder)
                if status != "OK": continue

                # Search for all messages
                status, messages = mail.search(None, "ALL")
                if status == "OK":
                    email_ids = messages[0].split()

                    # Limit processing to the last 10 emails for performance
                    recent_ids = email_ids[-10:] if len(email_ids) > 10 else email_ids

                    for e_id in recent_ids:
                        try:
                            # Fetch email header and content
                            res, msg_data = mail.fetch(e_id, "(RFC822)")
                            for r_part in msg_data:
                                if isinstance(r_part, tuple):
                                    msg = email.message_from_bytes(r_part[1])
                                    date_s = msg.get("Date")
                                    if not date_s: continue

                                    # Parse date to timestamp
                                    try:
                                        dt = parsedate_to_datetime(date_s)
                                        ts = int(dt.timestamp())
                                    except:
                                        continue

                                    # Process only if the email is newer than the last check
                                    if ts > last_check:
                                        raw_subj = msg["Subject"] or ""
                                        try:
                                            s_h = decode_header(raw_subj)[0]
                                            subj = clean_text(s_h[0], s_h[1])
                                        except:
                                            subj = str(raw_subj)

                                        orig_name, orig_email = get_clean_sender_info(msg)

                                        # Check if email is older than 24 hours
                                        if (current_timestamp - ts) > ONE_DAY:
                                            context.log(f"[{user_email}] Old mail. Alerting.")
                                            # Send a failure alert instead of forwarding
                                            ok, err = send_alert_central(target_email, subj,
                                                                         orig_name)
                                            if ok and ts > max_ts: max_ts = ts
                                        else:
                                            # Standard forwarding
                                            context.log(f"[{user_email}] New: {subj}")
                                            body, is_html, atts = get_email_content_and_attachments(
                                                msg)
                                            ok, err = send_forward_central(target_email, subj,
                                                                           orig_name, orig_email,
                                                                           body, is_html, atts)
                                            if ok:
                                                context.log(
                                                    f"[{user_email}] -> Forwarded via Gmail.")
                                                if ts > max_ts: max_ts = ts
                                            else:
                                                context.error(f"[{user_email}] -> Failed: {err}")
                        except:
                            continue
            except:
                pass

        # Update the database with the timestamp of the newest processed email
        if max_ts > last_check:
            context.log(f"[{user_email}] Updating DB: {max_ts}")
            databases.update_document(db_id, col_id, doc_id, {"last_check": max_ts})

    except Exception as e:
        context.error(f"[{user_email}] Error: {e}")
    finally:
        # Close connection and logout safely
        if mail:
            try:
                mail.close()
            except:
                pass
            try:
                mail.logout()
            except:
                pass


def main(context):
    """
    Entry point for the Appwrite Cloud Function.
    Initializes the client, fetches accounts, and starts processing.
    """
    api_key = os.environ.get("APPWRITE_API_KEY")
    db_id = os.environ.get("DATABASE_ID")
    col_id = os.environ.get("COLLECTION_ID")

    # Verify required environment variables
    if not os.environ.get("CENTRAL_SMTP_USER"):
        return context.res.json({"error": "Missing CENTRAL_SMTP_USER"}, 500)

    if not api_key or not db_id:
        return context.res.json({"error": "Config missing"}, 500)

    # Initialize Appwrite services
    client = (Client().set_endpoint(os.environ["APPWRITE_FUNCTION_API_ENDPOINT"]).set_project(
        os.environ["APPWRITE_FUNCTION_PROJECT_ID"]).set_key(api_key))
    databases = Databases(client)

    try:
        current_ts = int(time.time())
        # Fetch list of email accounts to process
        response = databases.list_documents(db_id, col_id)
        docs = response.get("documents", [])

        context.log(f"Checking {len(docs)} accounts...")
        # Iterate over each account
        for doc in docs:
            process_single_account(doc, databases, current_ts, context)

        return context.res.json({"status": "completed"})
    except Exception as e:
        return context.res.json({"error": str(e)}, 500)