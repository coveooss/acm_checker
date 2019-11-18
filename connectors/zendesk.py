from zdesk import Zendesk
from zdesk import get_id_from_url


def generate_zendesk_ticket(config, subject, description):
    client_config = {
        "zdesk_email": config["zdesk_user"],
        "zdesk_password": config["zdesk_password"],
        "zdesk_url": config["zdesk_url"],
        "zdesk_token": config["zdesk_token"],
    }

    # Auth
    zendesk = Zendesk(**client_config)

    # Define ticket
    new_ticket = {
        "ticket": {
            "requester": {"name": config["requester_name"], "email": config["requester_email"]},
            "subject": subject,
            "description": "Details in comment",
            "tags": config["tags"],
            "type": config["ticket_type"],
            "priority": "normal",
            "group_id": config["group_id"],
            "custom_fields": config["custom_fields"],
        }
    }

    ticket_content = {
        "ticket": {
            "comment":{
                "html_body": description
            }
        }
    }

    result = zendesk.ticket_create(data=new_ticket)
    ticket_id = get_id_from_url(result)
    zendesk.ticket_update(ticket_id, data=ticket_content)