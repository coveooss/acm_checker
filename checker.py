import boto3
import click
import logging
import yaml
import datetime
import pytz
import connectors
import re
from tabulate import tabulate

REGION = "us-east-1"

def notify(config, expirings_certs):

    global REGION

    for expirings_cert in expirings_certs:
        title, message = format_message(expirings_cert)
        for notifier_config in config["notifiers"]:
            if notifier_config.get("type", "").lower() == "zendesk":
                try:
                  logging.info("Created zendesk ticket for {}".format(expirings_cert["CertName"]))
                  connectors.generate_zendesk_ticket(notifier_config, title, message)
                except Exception as e:
                    logging.error("Can't create zendesk ticket: {}".format(e))

def format_message(expiring_cert):
    global REGION
    resource_infos = []
    elbs_v1 = []
    elbs_v2 = []
    all_infos_retrieved = False
    count = 0
    for resource in expiring_cert["InUseBy"]:
        if is_loadbalancer(resource):
            name = is_classic_elb(resource)
            if name:
                elbs_v1.append(name)
            else:
                elbs_v2.append(resource)
        else:
            resource_infos.append({
                'name': resource,
                'type': "unknown",
                'tags': "None"
            })

    if elbs_v2:
        clientv2 = boto3.client('elbv2', region_name=REGION)
        while not all_infos_retrieved:
            if count+19 > len(elbs_v2):
                tags = clientv2.describe_tags(ResourceArns=elbs_v2[count:len(elbs_v2)])
            else:
                tags = clientv2.describe_tags(ResourceArns=elbs_v2[count:count + 19])
            for info in tags["TagDescriptions"]:
                resource_infos.append({
                    'name': info["ResourceArn"],
                    'type': "elbv2",
                    'tags': ["{}:{}".format(tag["Key"],tag["Value"]) for tag in info["Tags"]]
                })
            if len(elbs_v2) > count + 19:
                count += 19
                continue
            all_infos_retrieved = True

    if elbs_v1:
        clientv1 = boto3.client('elb', region_name=REGION)
        all_infos_retrieved = False
        count = 0
        while not all_infos_retrieved:
            if count+19 > len(elbs_v1):
                tags = clientv1.describe_tags(LoadBalancerNames=elbs_v1[count:len(elbs_v1)])
            else:
                tags = clientv1.describe_tags(LoadBalancerNames=elbs_v1[count:count + 19])
            for info in tags["TagDescriptions"]:
                resource_infos.append({
                    'name': info["LoadBalancerName"],
                    'type': "elb",
                    'tags': ["{}:{}".format(tag["Key"],tag["Value"]) for tag in info["Tags"]]
                })
            if len(elbs_v1) > count + 19:
                count += 19
                continue
            all_infos_retrieved = True

    formated_infos = tabulate(resource_infos, headers="keys", tablefmt="html")

    title = "{} - Certificate {} is going to expire".format(expiring_cert["Criticality"], expiring_cert["CertName"])
    message = """
    <b>{}</b> is going to expire ({}).<br>
    <b>DomainName</b>: {}<br>
    <b>Region</b>: {}<br>
    <b>Still used by :</b><br>
    {}
    <br>
    This probably means that the rotation of the service hasn't been done yet. Contact the team to trigger a new deployment.
    """.format(expiring_cert["CertName"], expiring_cert["ExpireDate"], expiring_cert["DomainName"], REGION, formated_infos)

    return title, message

def is_classic_elb(arn):
    if not re.match(r".*loadbalancer/app.*", arn):
        m = re.match(r"\w+:\w+:\w+:\S+:\w+\/(\S+)", arn)
        return m.groups()[0]
    return False


def is_loadbalancer(resource):
    return bool(re.match(r".*loadbalancer.*", resource))

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
    global REGION

    if "acm_region" in config_file:
        REGION = config_file["acm_region"]

    client = boto3.client('acm', region_name=REGION)

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
                criticality= 'Critical'
            elif today > cert_detail["Certificate"]["NotAfter"] - datetime.timedelta(days = config["warning_day_limit"]):
                criticality= 'Warning'
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