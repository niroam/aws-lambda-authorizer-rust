output "lambda_function_arn" {
  description = "The ARN of the lambda function resource"
  value       = aws_lambda_function.lambda_function.arn
}

output "lambda_role_arn" {
  description = "The ARN of the lambda functions IAM role resource"
  value       = aws_iam_role.lambda_role.arn
}

output "lambda_role_name" {
  description = "The name of the lambda functions IAM role resource"
  value       = aws_iam_role.lambda_role.name
}

output "lambda_invoke_arn" {
  description = "The invoke ARN of the lambda function resource (APIGW)"
  value       = aws_lambda_function.lambda_function.invoke_arn
}

output "lambda_function_name" {
  description = "The name of the lambda function"
  value       = aws_lambda_function.lambda_function.function_name
}