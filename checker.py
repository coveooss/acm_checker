import boto3
import click
import logging
import yaml
import datetime
import pytz
import connectors
import re
from tabulate import tabulate
from botocore.exceptions import ClientError

REGION = "us-east-1"

def notify(config, expirings_certs, notification_db):
    """
    Iterate over all expiring certificates and notify every endpoint
    :param config: Config read from config file
    :param expirings_certs: list of unnotified expiring certificates
    :param notification_db: DynamoDB object where record of notification are stored.
    """

    global REGION

    for expirings_cert in expirings_certs:
        title, message = format_message(expirings_cert)
        notified = False
        for notifier_config in config["notifiers"]:
            if notifier_config.get("type", "").lower() == "zendesk":
                try:
                  logging.info("Created zendesk ticket for {}".format(expirings_cert["CertName"]))
                  connectors.generate_zendesk_ticket(notifier_config, title, message)
                  notified = True
                except Exception as e:
                    logging.error("Can't create zendesk ticket: {}".format(e))
            if notified:
                add_notified_cert(notification_db, expirings_cert["CertName"], expirings_cert["Criticality"])

def format_message(expiring_cert):
    """
    Create an HTML formatted message for the notification
    :param expiring_cert: cert info
    :return: Tuple with subject an body
    """
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
    """
    Test ELB version
    :param arn: ELB arn
    :return: True if ELBv1 false if ELBv2
    """
    if not re.match(r".*loadbalancer/app.*", arn):
        m = re.match(r"\w+:\w+:\w+:\S+:\w+\/(\S+)", arn)
        return m.groups()[0]
    return False


def is_loadbalancer(resource):
    """
    Test if the given resource arn stick to an ELB
    :param resource: Resource arn
    :return: True if it's an ELB, false if not
    """
    return bool(re.match(r".*loadbalancer.*", resource))


def get_notified_certs(table):
    """
    Retrieve all past notifications
    :param table: Dynamo table use to store record
    :return: Return true if succeed
    """
    try:
        response = table.scan()
    except ClientError as e:
        raise(e)
    else:
        return [ (cert["arn"], cert["criticality"]) for cert in response['Items']]


def add_notified_cert(table, arn, criticality):
    """
    Add record about a notification for given arn
    :param table: Dynamo table use to store record
    :param arn: arn of the certificate
    :return: Return true if succeed
    """
    try:
        response = table.put_item(
            Item={
                'arn': arn,
                'notifiedTime': str(datetime.datetime.utcnow()),
                'criticality': criticality
            }
        )
    except Exception as e:
        raise(e)
    else:
        logging.info("{} successfully added to DynamoDB (ID : {})".format(
            arn, response['ResponseMetadata']['RequestId']))
        return True


def del_notified_cert(table, arn):
    """
    Delete notification record if certificate doesn't exist anymore
    :param table: Dynamo table use to store record
    :param arn: arn of the certificate
    :return: Return true if succeed
    """
    try:
        response = table.delete_item(
            Key={
                'arn': arn
            }
        )
    except ClientError as e:
        raise(e)
    else:
        logging.info("{} successfully deleted from DynamoDB (ID : {})".format(
            arn, response['ResponseMetadata']['RequestId']))
        return True

@click.command()
@click.option("--config_file", default="config.yaml", help="Specify the config to use")
def main(config_file):

    # Init
    logging.basicConfig(
        format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)

    with open(config_file, 'r') as stream:
        try:
            config = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            logging.error("Unable to parse file {} : {}".format(config_file, exc))

    expiring_certs = []
    global REGION

    if "acm_region" in config:
        REGION = config["acm_region"]
    dynamodb_table_name = config["dynamo_db_name"]

    client = boto3.client('acm', region_name=REGION)

    dynamodb = boto3.resource('dynamodb', region_name=REGION)
    dynamo_table = dynamodb.Table(dynamodb_table_name)

    acm_certs = client.list_certificates(
        CertificateStatuses=['ISSUED'],
        MaxItems=123
    )

    # Retrieve certificate for which notification has already been done
    already_notified = get_notified_certs(dynamo_table)

    # Check ACM certificate expiration date
    today = pytz.UTC.localize(datetime.datetime.now())
    for cert in acm_certs["CertificateSummaryList"]:
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

            if (cert_detail["Certificate"]["CertificateArn"], criticality) not in already_notified:
                expiring_certs.append({
                    'CertName': cert_detail["Certificate"]["CertificateArn"],
                    'ExpireDate': cert_detail["Certificate"]["NotAfter"],
                    'InUseBy': cert_detail["Certificate"]["InUseBy"],
                    'DomainName': cert_detail["Certificate"]["DomainName"],
                    'Criticality': criticality,
                })

    # Start notification process
    if expiring_certs:
        notify(config, expiring_certs, dynamo_table)

    # Clear DynamoDB
    for (arn, criticality) in already_notified:
        if arn not in [cert["CertificateArn"] for cert in acm_certs["CertificateSummaryList"]]:
            logging.info("Delete {} from db since it isn't in acm anymore".format(arn))
            del_notified_cert(dynamo_table, arn)

    logging.info("ACM Check Complete")
if __name__ == "__main__":
    main()