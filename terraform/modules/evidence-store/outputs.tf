output "bucket_name" {
  value = aws_s3_bucket.evidence.bucket
}

output "bucket_arn" {
  value = aws_s3_bucket.evidence.arn
}

output "kms_key_arn" {
  value = aws_kms_key.this.arn
}

output "kms_alias" {
  value = aws_kms_alias.this.name
}
