output "logs_bucket" {
  value = aws_s3_bucket.logs.bucket
}

output "lambda_name" {
  value = aws_lambda_function.remediacion.function_name
}