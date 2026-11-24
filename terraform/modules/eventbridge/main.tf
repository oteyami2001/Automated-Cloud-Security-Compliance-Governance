# Event routing (docs/architecture.md §3.2): one narrow rule per source on the default bus. aws.*
# sources cannot be put by account principals, so only AWS services can trigger these rules. The
# synthetic rule exists only when allow_synthetic_events = true (dev).

locals {
  cloudtrail_event_names = [
    "StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors",
    "AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress", "AuthorizeSecurityGroupEgress",
    "RevokeSecurityGroupEgress", "ModifySecurityGroupRules",
    "PutBucketPolicy", "DeleteBucketPolicy", "PutBucketPublicAccessBlock", "DeleteBucketPublicAccessBlock", "PutBucketAcl",
    "StopConfigurationRecorder", "DeleteConfigurationRecorder", "PutConfigurationRecorder", "DeleteDeliveryChannel", "DeleteConfigRule",
  ]

  base_rules = {
    config-compliance = {
      description = "AWS Config compliance changes for this project's rules"
      pattern = {
        source        = ["aws.config"]
        "detail-type" = ["Config Rules Compliance Change"]
        detail        = { configRuleName = [{ prefix = "acscg-" }] }
      }
    }
    cloudtrail-changes = {
      description = "Security-relevant configuration changes (SEC-012, SEC-015)"
      pattern = {
        source        = ["aws.ec2", "aws.s3", "aws.cloudtrail", "aws.config"]
        "detail-type" = ["AWS API Call via CloudTrail"]
        detail        = { eventName = local.cloudtrail_event_names }
      }
    }
    access-analyzer = {
      description = "IAM Access Analyzer findings"
      pattern = {
        source        = ["aws.access-analyzer"]
        "detail-type" = ["Access Analyzer Finding"]
      }
    }
    ssm-status = {
      description = "Remediation runbook status changes"
      pattern = {
        source        = ["aws.ssm"]
        "detail-type" = ["EC2 Automation Execution Status-change Notification"]
        detail        = { Definition = [{ prefix = "acscg-" }] }
      }
    }
  }

  optional_rules = merge(
    var.enable_security_hub ? {
      securityhub = {
        description = "Security Hub CSPM findings (Config-generated findings excluded; ingested directly)"
        pattern = {
          source        = ["aws.securityhub"]
          "detail-type" = ["Security Hub Findings - Imported"]
          detail        = { findings = { ProductFields = { "aws/securityhub/ProductName" = [{ "anything-but" = "Config" }] } } }
        }
      }
    } : {},
    var.enable_guardduty ? {
      guardduty = {
        description = "GuardDuty findings, severity 4 and above (report-only)"
        pattern = {
          source        = ["aws.guardduty"]
          "detail-type" = ["GuardDuty Finding"]
          detail        = { severity = [{ numeric = [">=", 4] }] }
        }
      }
    } : {},
    var.allow_synthetic_events ? {
      synthetic = {
        description = "Synthetic test events (dev only; never remediated)"
        pattern     = { source = ["acscg.synthetic"] }
      }
    } : {},
  )

  rules = merge(local.base_rules, local.optional_rules)
}

resource "aws_cloudwatch_event_rule" "this" {
  for_each      = local.rules
  name          = "${var.name_prefix}-${each.key}"
  description   = each.value.description
  event_pattern = jsonencode(each.value.pattern)
}

resource "aws_cloudwatch_event_target" "processor" {
  for_each = local.rules
  rule     = aws_cloudwatch_event_rule.this[each.key].name
  arn      = var.processor_arn

  retry_policy {
    maximum_retry_attempts       = 2
    maximum_event_age_in_seconds = 3600
  }

  dead_letter_config {
    arn = var.dlq_arn
  }
}

resource "aws_lambda_permission" "processor" {
  for_each      = local.rules
  statement_id  = "AllowEventBridge-${each.key}"
  action        = "lambda:InvokeFunction"
  function_name = var.processor_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.this[each.key].arn
}

resource "aws_sqs_queue_policy" "dlq" {
  queue_url = var.dlq_url
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "EventBridgeDeadLetters"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = var.dlq_arn
      Condition = { ArnEquals = { "aws:SourceArn" = [for r in aws_cloudwatch_event_rule.this : r.arn] } }
    }]
  })
}
