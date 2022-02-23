module "tenant_authorizer_lambda" {
  source = "../terraform-aws-modules/lambda-module"

  lambda_function_name = "${module.project_label.id}-tenant-authorizer"
  //lambda_source        = "${path.root}/../../code/target/x86_64-unknown-linux-gnu/release/lambda_tenant_authorizer.zip"
  lambda_source        = "${path.root}/../../code/target/aarch64-unknown-linux-gnu/release/lambda_tenant_authorizer.zip"
  lambda_policy_list = {
    policy_1 = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  }
  lambda_env_variables = {
    ENV_NAME = "demo" //module.project_label.stage
    // Need to update with Valid Issuer list and the JWK's
    VALID_ISSUERS = "[\"https://rust.blueprint.auth.com\"]"
    JWKS_STRING = <<EOF
{
  "keys": [
    {
      "kty": "RSA",
      "n": "6S7asUuzq5Q_3U9rbs-PkDVIdjgmtgWreG5qWPsC9xXZKiMV1AiV9LXyqQsAYpCqEDM3XbfmZqGb48yLhb_XqZaKgSYaC_h2DjM7lgrIQAp9902Rr8fUmLN2ivr5tnLxUUOnMOc2SQtr9dgzTONYW5Zu3PwyvAWk5D6ueIUhLtYzpcB-etoNdL3Ir2746KIy_VUsDwAM7dhrqSK8U2xFCGlau4ikOTtvzDownAMHMrfE7q1B6WZQDAQlBmxRQsyKln5DIsKv6xauNsHRgBAKctUxZG8M4QJIx3S6Aughd3RZC4Ca5Ae9fd8L8mlNYBCrQhOZ7dS0f4at4arlLcajtw",
      "e": "AQAB",
      "kid": "test-rsa",
      "alg":"RS256"
    },
    {
      "kty": "EC",
      "crv": "P-521",
      "x": "AYeAr-K3BMaSlnrjmszuJdOYBstGJf0itM2TTGwsaO0-cGcXor8f0LPXbB9B_gLK7m0th3okXzypIrq-qgTMsMig",
      "y": "AGLdv92aARm6efe_sEJyRJ-n4IBxhMRTm6wIe8AZhlkdLWxzEyfusiXLZHon1Ngt_Q8d_PYWYrbJVWS7VrnK05bJ",
      "kid": "test-ec",
      "alg":"RS256"
    }
  ]
}
EOF
  }
  lambda_handler     = "main"
  lambda_memory_size = 256
  lambda_timeout     = 5

  lambda_tags = module.project_label.tags

  lambda_log_subscription_enabled = false

  lambda_runtime = "provided.al2"

  lambda_architecture = "arm64"
}