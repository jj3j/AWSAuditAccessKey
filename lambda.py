from collections import defaultdict
from datetime import datetime, timezone
import logging

import boto3
from botocore.exceptions import ClientError

# IAM Date Config
ALERT_AFTER_N_DAYS = 365
iam_client = boto3.client("iam")

# AWS SNS Config
SNS_CLIENT = boto3.client("sns")
SNS_TOPIC = "arn:aws:sns:"
SNS_SUBJECT = "Access Key Expired"


def is_key_interesting(key):
    if key["Status"] != "Active":
        return False

    elapsed_days = (datetime.now(timezone.utc) - key["CreateDate"]).days
    if elapsed_days < ALERT_AFTER_N_DAYS:
        return False

    return True


def lambda_handler(event, context):
    users = []
    is_truncated = True
    marker = None
    while is_truncated:
        response = iam_client.list_users(
            **{k: v for k, v in (dict(Marker=marker)).items() if v is not None}
        )
        users.extend(response["Users"])
        is_truncated = response["IsTruncated"]
        marker = response.get("Marker", None)
    filtered_users = list(filter(lambda u: u.get("UserName"), users))

    interesting_keys = []

    for user in filtered_users:
        response = iam_client.list_access_keys(UserName=user["UserName"])
        access_keys = response["AccessKeyMetadata"]

        interesting_keys.extend(
            list(filter(lambda k: is_key_interesting(k), access_keys))
        )

    interesting_keys_grouped_by_user = defaultdict(list)
    for key in interesting_keys:
        interesting_keys_grouped_by_user[key["UserName"]].append(key)

    for user in interesting_keys_grouped_by_user.values():
        sns_message = ",".join([str(i) for i in user])
        SNS_CLIENT.publish(TopicArn=SNS_TOPIC, Message=sns_message, Subject=SNS_SUBJECT)
