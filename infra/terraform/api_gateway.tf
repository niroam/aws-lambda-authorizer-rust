resource "aws_api_gateway_rest_api" "api_gateway" {
  name        = "${module.project_label.id}-api-gateway"
  description = "This is the inventory manager api"
  endpoint_configuration {
    types = ["REGIONAL"]
  }

  tags   = module.project_label.tags
}

resource "aws_api_gateway_resource" "secure_resource" {
  rest_api_id = aws_api_gateway_rest_api.api_gateway.id
  parent_id   = aws_api_gateway_rest_api.api_gateway.root_resource_id
  path_part   = "SecureResource"
}

resource "aws_api_gateway_method" "secure_resource_method" {
  rest_api_id   = aws_api_gateway_rest_api.api_gateway.id
  resource_id   = aws_api_gateway_resource.secure_resource.id
  http_method   = "GET"
  authorization = "CUSTOM"
  authorizer_id = aws_api_gateway_authorizer.api_authorizer.id
}

resource "aws_api_gateway_integration" "secure_resource_intergration" {
  rest_api_id          = aws_api_gateway_rest_api.api_gateway.id
  resource_id          = aws_api_gateway_resource.secure_resource.id
  http_method          = aws_api_gateway_method.secure_resource_method.http_method
  type                 = "MOCK"
  request_templates = {
    "application/json" = <<EOF
{
   "statusCode" : 200
}
EOF
  }
}

resource "aws_api_gateway_method_response" "secure_resource_response_200" {
  rest_api_id = aws_api_gateway_rest_api.api_gateway.id
  resource_id = aws_api_gateway_resource.secure_resource.id
  http_method = aws_api_gateway_method.secure_resource_method.http_method
  status_code = "200"
}

resource "aws_api_gateway_integration_response" "MyDemoIntegrationResponse" {
  rest_api_id = aws_api_gateway_rest_api.api_gateway.id
  resource_id = aws_api_gateway_resource.secure_resource.id
  http_method = aws_api_gateway_method.secure_resource_method.http_method
  status_code = aws_api_gateway_method_response.secure_resource_response_200.status_code

  # Transforms the backend JSON response to XML
response_templates = {
    "application/json" = <<EOF
{
  "message" : "hello"
}
EOF
  }
  
}

# Authorizer
resource "aws_api_gateway_authorizer" "api_authorizer" {
  name                   = "${module.project_label.id}-api-authorizer"
  rest_api_id            = aws_api_gateway_rest_api.api_gateway.id
  authorizer_uri         = module.tenant_authorizer_lambda.lambda_invoke_arn
  authorizer_credentials = aws_iam_role.api_authorizer_invocation_role.arn
  authorizer_result_ttl_in_seconds = 0
}

resource "aws_iam_role" "api_authorizer_invocation_role" {
  name = "${module.project_label.id}-api-authorizer-invoke"
  path = "/"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "apigateway.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "api_authorizer_invocation_policy" {
  name = "${module.project_label.id}-api-authorizer-invoke"
  role = aws_iam_role.api_authorizer_invocation_role.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "lambda:InvokeFunction",
      "Effect": "Allow",
      "Resource": "${module.tenant_authorizer_lambda.lambda_function_arn}"
    }
  ]
}
EOF
}

resource "aws_iam_role" "api_authorizer_access_role" {
  name = "${module.project_label.id}-api-authorizer-access"
  path = "/"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "AWS": [
          "${aws_iam_role.api_authorizer_invocation_role.arn}",
          "arn:aws:sts::${data.aws_caller_identity.current.account_id}:assumed-role/${module.tenant_authorizer_lambda.lambda_role_name}/${module.tenant_authorizer_lambda.lambda_function_name}"
          ]
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "api_authorizer_access_policy" {
  name = "${module.project_label.id}-api-authorizer-access"
  role = aws_iam_role.api_authorizer_access_role.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
          "dynamodb:UpdateItem",
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:DeleteItem",
          "dynamodb:Query",          
          "dynamodb:Scan"
      ],
      "Resource": [
        "arn:aws:dynamodb:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:table/${module.project_label.stage}-*"
      ]
    }
  ]
}
EOF
}

resource "aws_api_gateway_deployment" "demo" {
  rest_api_id = aws_api_gateway_rest_api.api_gateway.id

  //triggers = {
  //  redeployment = sha1(jsonencode(aws_api_gateway_rest_api.example.body))
  //}

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_api_gateway_stage" "demo" {
  deployment_id = aws_api_gateway_deployment.demo.id
  rest_api_id   = aws_api_gateway_rest_api.api_gateway.id
  stage_name    = "demo"
}
