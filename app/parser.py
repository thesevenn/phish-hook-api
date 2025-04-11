from email import message_from_string
from email.utils import parseaddr
from email.policy import default

from app.filters.ruleset import Ruleset

class EmailParser:
    def __init__( self, raw_data:bytes ):
        self.email_content:str = raw_data.decode('utf-8')
        self.features = self.__extract_features()

    @staticmethod
    def format_sender( sender:str ):
        display_name, sender_email = parseaddr(sender)
        sender_domain = Ruleset.url_domain(sender_email.split('@')[-1] if '@' in sender_email else '')

        return display_name,sender_email,sender_domain

    def __extract_features( self ):
        email = message_from_string(self.email_content, policy=default)
        subject = email["Subject"] or ""
        sender = email["From"]
        recipient = email["To"]
        reply_to = email["Reply-To"] if email["Reply-To"] else sender
        date = email["Date"]
        message_id = email["Message-ID"]
        content_text = ""
        content_html = ""
        unsafe_types = {"application/pdf", "application/octet-stream", "application/x-msdownload"}
        if email.is_multipart():
            for part in email.walk():
                content_type = part.get_content_type()
                if content_type in unsafe_types:
                    continue
                content_charset = part.get_content_charset() or "utf-8"

                if content_type == "text/plain" and not content_text:
                    content_text = part.get_payload(decode=True).decode(content_charset, errors="ignore")

                elif content_type == "text/html" and not content_html:
                    content_html = part.get_payload(decode=True).decode(content_charset, errors="ignore")

        else:  # If not multipart, extract payload
            content_charset = email.get_content_charset() or "utf-8"
            content_text = email.get_payload(decode=True).decode(content_charset, errors="ignore")

        features = {
            "message_id":message_id,
            "sender":self.format_sender(sender),
            "recipient":recipient,
            "reply_to":self.format_sender(reply_to),
            "date":date,
            "subject":subject,
            "body_text":content_text.replace("\n"," "),
            "body_html":content_html if content_html else "",
            "raw_email":email,
        }
        return features

    # Possible extension analysis of attachments
