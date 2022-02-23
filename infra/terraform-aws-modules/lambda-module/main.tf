# Create IAM role for the Lambda function
# Give assume role permissions to the lambda service to allow invocation
resource "aws_iam_role" "lambda_role" {
  name               = lower("${var.lambda_function_name}_lambda_role")
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

# Attach IAM policies as per input variable
resource "aws_iam_role_policy_attachment" "lambda_role_policy_attach" {
  for_each = var.lambda_policy_list
  role       = aws_iam_role.lambda_role.name
  policy_arn = each.value
}

# Create a cloudwatch log group so that we can control the retention period
resource "aws_cloudwatch_log_group" "lambda_log_group" {
  name              = "/aws/lambda/${var.lambda_function_name}"
  retention_in_days = 30
  tags = var.lambda_tags
}


resource "aws_cloudwatch_log_subscription_filter" cdcjobconsumer_log_subscription {
  count           = var.lambda_log_subscription_enabled? 1 : 0
  name            = "${var.lambda_function_name}-log-filter"
  log_group_name  = aws_cloudwatch_log_group.lambda_log_group.name
  destination_arn = var.log_subscription_destination
  filter_pattern  = var.log_subscription_filter_pattern
}


resource "aws_lambda_function" "lambda_function" {
  filename      = var.lambda_source
  function_name = var.lambda_function_name
  role          = aws_iam_role.lambda_role.arn
  handler       = var.lambda_handler
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory_size
  environment {
    variables = var.lambda_env_variables
  }
  source_code_hash = filebase64sha256(var.lambda_source)

  runtime = var.lambda_runtime

  architectures = [var.lambda_architecture]

  dynamic vpc_config {
    for_each = var.lambda_vpc_config == null ? [] : [var.lambda_vpc_config]

    content {
      security_group_ids = vpc_config.value.security_group_ids
      subnet_ids         = vpc_config.value.subnet_ids
    }
  }

  tags = var.lambda_tags

  depends_on = [aws_cloudwatch_log_group.lambda_log_group]
}

# Attache any Triggers for Queues
resource "aws_lambda_event_source_mapping" "lambda_sqs_trigger" {
  for_each = var.lambda_sqs_trigger_list
  event_source_arn = each.value["queue_arn"]
  function_name    = aws_lambda_function.lambda_function.arn
  batch_size       = each.value["batch_size"]
}
