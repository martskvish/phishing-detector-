"""Simple feature switches for the phishing detector app.

Change ``SEND_2FA`` to ``True`` when the server can send email OTP messages.
Keep it ``False`` on providers that do not support SMTP/email sending so users
can register with only username, email, and password.
"""

SEND_2FA = False


def signup_2fa_enabled():
    """Return whether signup should send and require an email OTP."""
    return SEND_2FA is True