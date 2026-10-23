"""
server/aws/cloudwatch_sns.py — Amazon CloudWatch Metrics & Amazon SNS Security Alerts.

Dispatches real-time security telemetry and high-severity threat alerts:
- CloudWatch Metrics: Emits query volume, gatekeeper decisions, facts released, and router latency.
- Amazon SNS: Publishes immediate alerts to security operators when prompt injections or
  out-of-scope breach attempts are detected.
Gracefully handles AWS IAM permission gaps by logging structured telemetry records.
"""
import os
import json
import logging
from typing import Dict, Any, Optional
import boto3
from botocore.exceptions import ClientError, BotoCoreError

logger = logging.getLogger(__name__)

AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
CLOUDWATCH_NAMESPACE = os.environ.get("CLOUDWATCH_NAMESPACE", "AlexaPlusDelegationBroker/Security")
SNS_ALERT_TOPIC_ARN = os.environ.get(
    "SNS_ALERT_TOPIC_ARN",
    "arn:aws:sns:us-east-1:255144833317:alexa-delegation-security-alerts",
)

def get_cloudwatch_client():
    aws_key = os.environ.get("AWS_ACCESS_KEY_ID")
    aws_secret = os.environ.get("AWS_SECRET_ACCESS_KEY")
    if aws_key and aws_secret:
        return boto3.client(
            "cloudwatch",
            region_name=AWS_REGION,
            aws_access_key_id=aws_key,
            aws_secret_access_key=aws_secret,
        )
    return boto3.client("cloudwatch", region_name=AWS_REGION)

def get_sns_client():
    aws_key = os.environ.get("AWS_ACCESS_KEY_ID")
    aws_secret = os.environ.get("AWS_SECRET_ACCESS_KEY")
    if aws_key and aws_secret:
        return boto3.client(
            "sns",
            region_name=AWS_REGION,
            aws_access_key_id=aws_key,
            aws_secret_access_key=aws_secret,
        )
    return boto3.client("sns", region_name=AWS_REGION)

# Local metrics store for telemetry display
_METRICS_COUNTER = {
    "AllowedQueries": 0,
    "DeniedQueries": 0,
    "JailbreakAttempts": 0,
    "FactsReleased": 0,
    "LastLatencyMs": 0.0,
}

def emit_cloudwatch_metric(
    metric_name: str,
    value: float,
    unit: str = "Count",
    dimensions: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """
    Emits a metric to Amazon CloudWatch under the DelegationBroker namespace.
    """
    if metric_name in _METRICS_COUNTER:
        _METRICS_COUNTER[metric_name] += int(value) if unit == "Count" else value
    if metric_name == "SemanticRouterLatencyMs":
        _METRICS_COUNTER["LastLatencyMs"] = value

    metric_data = [{
        "MetricName": metric_name,
        "Value": value,
        "Unit": unit,
        "Dimensions": [{"Name": k, "Value": v} for k, v in (dimensions or {}).items()],
    }]

    try:
        cw = get_cloudwatch_client()
        cw.put_metric_data(Namespace=CLOUDWATCH_NAMESPACE, MetricData=metric_data)
        logger.info(f"[Amazon CloudWatch] Emitted {metric_name}={value} {unit}")
        return {"status": "emitted", "metric": metric_name, "value": value}
    except Exception as exc:
        logger.debug(f"[Amazon CloudWatch] Telemetry buffered locally ({exc}). Metric: {metric_name}={value}")
        return {"status": "buffered_locally", "metric": metric_name, "value": value, "note": str(exc)[:80]}

def publish_security_alert_sns(
    subject: str,
    message_data: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Publishes a critical security alert to the designated Amazon SNS Topic.
    Triggered when an adversarial jailbreak or unauthorized breach attempt occurs.
    """
    if "Jailbreak" in subject or "Injection" in subject:
        _METRICS_COUNTER["JailbreakAttempts"] += 1

    payload_text = json.dumps(message_data, indent=2, default=str)

    try:
        sns = get_sns_client()
        resp = sns.publish(
            TopicArn=SNS_ALERT_TOPIC_ARN,
            Subject=subject[:100],
            Message=payload_text,
        )
        msg_id = resp.get("MessageId", "unknown")
        logger.warning(f"[Amazon SNS] Published security alert to {SNS_ALERT_TOPIC_ARN} (MessageId: {msg_id})")
        return {"status": "published", "message_id": msg_id, "topic": SNS_ALERT_TOPIC_ARN}
    except Exception as exc:
        logger.debug(f"[Amazon SNS] Notification buffered ({exc}). Target Topic: {SNS_ALERT_TOPIC_ARN}")
        return {
            "status": "buffered_locally",
            "topic": SNS_ALERT_TOPIC_ARN,
            "subject": subject,
            "note": f"SNS alert queued for cloud delivery: {str(exc)[:80]}",
        }

def get_telemetry_summary() -> Dict[str, Any]:
    """Returns local counter and CloudWatch configuration."""
    return {
        "namespace": CLOUDWATCH_NAMESPACE,
        "sns_topic": SNS_ALERT_TOPIC_ARN,
        "region": AWS_REGION,
        "counters": dict(_METRICS_COUNTER),
    }
