"""Pengiriman email (OTP). Backend 'smtp' untuk produksi; 'console' (pengembangan) menyimpan ke DEV_OUTBOX."""
from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage

import config

log = logging.getLogger("SeMediChain")
DEV_OUTBOX: list[dict] = []   # hanya terisi pada backend console


class MailError(Exception):
    pass


def send_mail(to: str, subject: str, body: str) -> None:
    # Selalu log ke terminal
    log.info(f"--- [EMAIL] Ke: {to} | Subjek: {subject} | Isi: {body} ---")
    
    # Rekam ke file log khusus untuk Demo (data/mail_outbox.log)
    try:
        import os
        from datetime import datetime
        log_path = os.path.join(config.DATA_DIR, "mail_outbox.log")
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] TO: {to} | SUBJ: {subject}\n{body}\n{'-'*50}\n")
    except Exception as e:
        log.error(f"Gagal menulis ke mail_outbox.log: {e}")

    if config.MAIL_BACKEND == "console":
        DEV_OUTBOX.append({"to": to, "subject": subject, "body": body})
        del DEV_OUTBOX[:-20]
        return
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = config.SMTP_FROM or config.SMTP_USER, to, subject
    msg.set_content(body)
    try:
        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=15) as smtp:
            if config.SMTP_STARTTLS:
                smtp.starttls(context=ssl.create_default_context())
            if config.SMTP_USER:
                smtp.login(config.SMTP_USER, config.SMTP_PASSWORD)
            smtp.send_message(msg)
    except (OSError, smtplib.SMTPException) as exc:
        log.error("Gagal mengirim email: %s", exc)
        raise MailError("Email tidak dapat dikirim saat ini. Coba lagi nanti.") from exc
