variable "lambda_function_name" {
  description = "The name of the lambda function."
}

variable "lambda_policy_list" {
  description = "List of IAM Policies that need to be attached to the lambda function"
  type = map(string)
}

variable "lambda_source" {
  description = "The location of the source code for the lambda function"
}

variable "lambda_handler" {
  description = "The lambda function handler name"
}

variable "lambda_timeout" {
  description = "The lambda function handler name"
}

variable "lambda_memory_size" {
  description = "The lambda function handler name"
}

variable "lambda_env_variables" {
  description = "The lambda function handler name"
  type = map(string)
}

variable "lambda_log_subscription_enabled" {
  description = "If we want the default log subscription filter to sumo"
  type = bool
}
variable "log_subscription_destination" {
  type = string
  default = ""
}
variable "log_subscription_filter_pattern" {
  default = ""
}

variable "lambda_tags" {
  description = "The tags we want to add to the lambda function"
}

variable "lambda_vpc_config" {
  description = "If the lambda needs to be deployed inside a VPC, the security group must be provided"
  type = object({
    security_group_ids = list(string)
    subnet_ids         = list(string)
  })
  default = null
}

variable "lambda_sqs_trigger_list" {
  description = "List of SQS ARN's and batch size that will be used as an event source mapping"
  type = map(object({
    queue_arn = string
    batch_size = number
  }))
  default = {}
}

variable "lambda_runtime" {
  type = string
  default = ""
}

variable "lambda_architecture" {
  type = string
  default = ""
}