import json
import os

import boto3
from botocore.exceptions import ClientError

s3 = boto3.client("s3")
sns = boto3.client("sns")

TOPIC_ARN = os.environ["TOPIC_ARN"]
PREFIJO = os.environ["PREFIJO"]
SID = "DenyInsecureTransport"


def avisar(asunto, mensaje):
    sns.publish(TopicArn=TOPIC_ARN, Subject=asunto, Message=mensaje)


def lambda_handler(event, context):
    bucket = event["detail"]["resourceId"]

    # Solo se corrigen automáticamente los buckets dentro del alcance
    if not bucket.startswith(PREFIJO):
        avisar(
            f"Bucket sin HTTPS obligatorio: {bucket}",
            f"El bucket {bucket} permite conexiones sin HTTPS. "
            f"Está fuera del alcance de la remediación automática, así que no se modificó.",
        )
        return {"bucket": bucket, "accion": "solo aviso"}

    try:
        politica = json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"])
    except ClientError as e:
        codigo = e.response["Error"]["Code"]
        if codigo == "NoSuchBucketPolicy":
            politica = {"Version": "2012-10-17", "Statement": []}
        elif codigo == "NoSuchBucket":
            return {"bucket": bucket, "accion": "el bucket ya no existe"}
        else:
            raise

    if any(s.get("Sid") == SID for s in politica["Statement"]):
        return {"bucket": bucket, "accion": "ya estaba corregido"}

    politica["Statement"].append(
        {
            "Sid": SID,
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
        }
    )
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(politica))

    avisar(
        f"Bucket corregido automáticamente: {bucket}",
        f"El bucket {bucket} permitía conexiones sin HTTPS. "
        f"Se agregó una política que las deniega.",
    )
    return {"bucket": bucket, "accion": "corregido"}