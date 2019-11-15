import boto3
import click
import logging
import yaml
import datetime
import pytz
import connectors


client = boto3.client('acm')

def notify(config, expirings_certs):
    for expirings_cert in expirings_certs:
        title = "{} - Certificate {} is going to expire".format(expirings_cert["Criticality"], expirings_cert["CertName"])
        message = """
        {} is going to expire and is still in use by :
        {}
        DomainName: {}

        This probably means that the rotation of the service hasn't been done yet. Contact the team to trigger a new deployment.
        """.format(expirings_cert["CertName"], expirings_cert["InUseBy"],expirings_cert["DomainName"])
        for notifier_config in config["notifiers"]:
            if notifier_config.get("type", "").lower() == "zendesk":
                try:
                  connectors.generate_zendesk_ticket(notifier_config, title, message)
                except Exception as e:
                    logging.error("Can't create zendesk ticket: {}".format(e))


@click.command()
@click.option("--config_file", default="config.yaml", help="Specify the config to use")
def main(config_file):
    logging.basicConfig(
        format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)

    with open(config_file, 'r') as stream:
        try:
            config = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            logging.error("Unable to parse file {} : {}".format(config_file, exc))

    expiring_certs = []


    certs = client.list_certificates(
        CertificateStatuses=['ISSUED'],
        MaxItems=123
    )

    today = pytz.UTC.localize(datetime.datetime.now())
    for cert in certs["CertificateSummaryList"]:
        cert_detail = client.describe_certificate(
            CertificateArn=cert["CertificateArn"]
        )

        if cert_detail["Certificate"]["InUseBy"]:
            if today > cert_detail["Certificate"]["NotAfter"] - datetime.timedelta(days = config["critical_day_limit"]):
                criticality= 'critical'
            elif today > cert_detail["Certificate"]["NotAfter"] - datetime.timedelta(days = config["warning_day_limit"]):
                criticality= 'warning'
            else:
                continue
            expiring_certs.append({
                'CertName': cert_detail["Certificate"]["CertificateArn"],
                'ExpireDate': cert_detail["Certificate"]["NotAfter"],
                'InUseBy': cert_detail["Certificate"]["InUseBy"],
                'DomainName': cert_detail["Certificate"]["DomainName"],
                'Criticality': criticality,
            })

    if expiring_certs:
        notify(config, expiring_certs)
if __name__ == "__main__":
    main()