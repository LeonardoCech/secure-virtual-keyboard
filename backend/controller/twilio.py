from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail


def send_email(api_key, lang, subject, to_emails, hotp_code, from_email='noreply@we-bronx.io', html_content=None):
    # using SendGrid's Python Library
    # https://github.com/sendgrid/sendgrid-python

    if html_content is None:
        # if there is no HTML content, use html from file src/email-templates/email-mfa-code.html
        html_content = open('src/email-templates/email-mfa-code_en-US.html', 'r').read()

    message = Mail(
        from_email=from_email,
        to_emails=to_emails,
        subject=subject,
        html_content=html_content.replace('{token}', hotp_code))

    try:
        sg = SendGridAPIClient(api_key)
        sg.send(message)
    except Exception as e:
        print(e.body)
