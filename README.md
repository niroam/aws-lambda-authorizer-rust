# Lambda Authorizer using Rust
AWS Lambda Multi Tenant Authorizer with Tenant Session Generation

![authorizer drawio](https://user-images.githubusercontent.com/7487453/156469571-4549b5ea-0d57-4c68-b1dd-5ac6780f84a3.png)

## How to deploy

**Compile/Test the rust code (Currently cross compiles to ARM using the Cross crate)**

    ./build.sh

**Deploy the cloud infra (Currently uses Terraform)**

    ./deploy

## Token Generation and Keys
Using https://token.dev/ we need to generate a token with valid signature and the public key to validate that signature. You can use the sample Header/Payload below to reverese engineer a valid token using the webapp at token.dev ( Make sure to update the expiary claim )

Example Token
Header

    {
      "typ": "JWT",
      "alg": "RS256",
      "kid": "test-rsa"
    }
Payload

    {
      "origin_jti": "b0661df2-26f1-471d-9080-8410743c90da",
      "custom:tenantId": "1234567xyz",
      "sub": "d1fdf006-3e99-415e-984e-b649beb2212f",
      "aud": "28iqrgirmnh3vc2dpldg4h19n",
      "event_id": "f0bbddfd-564f-4268-94b7-2b0e64f57d51",
      "token_use": "id",
      "auth_time": 1644823894,
      "iss": "https://rust.blueprint.auth.com",
      "cognito:username": "testUser",
      "exp": 1649568235,
      "iat": 1645564635,
      "jti": "63bce66b-150b-4fac-ba67-ffbfc57d8350"
    }

Ensure that that you update the tenant_authorizer.tf to contain the matching JWK with a matching kid to validate the signature

## Basic performance test
Ensure that the artillery configuration file has been updated with the URL endpoint for the API Gateway after deployment, we also need to include the new token generated in the step above in this file

    enter code here

**Execute Artillery CLI**

    cd test/loadtest/
    artillery run load-test.yml
    
**Cloudwatch log insights**

    filter @type="REPORT"
    | fields greatest(@initDuration, 0) + @duration as duration, ispresent(@initDuration) as coldStart
    | stats count(*) as count, pct(duration, 50) as p50, pct(duration, 90) as p90, pct(duration, 99) as p99, max(duration) as max by coldStart

![](https://lh6.googleusercontent.com/nbHoC8Jfc7Sh-_jOL992iQIRTzoXHO6QuLtbMStI0wW19cVL-P9tADx75KkYgYSmGFyK0u57NSZqWOi4LoVwIzGcy8zwdZViiysYWEdUHya_93NO_VEx9Lb3uQSNU_rSJlsM-aLS)


## Usefule Links

The AWS repositories below provide some great guidance on how to start with Rust + AWS Lambda

-   [https://github.com/awslabs/aws-lambda-rust-runtime](https://github.com/awslabs/aws-lambda-rust-runtime "https://github.com/awslabs/aws-lambda-rust-runtime")[](https://github.com/aws-samples/serverless-rust-demo "https://github.com/aws-samples/serverless-rust-demo")
-   [https://github.com/aws-samples/serverless-rust-demo](https://github.com/aws-samples/serverless-rust-demo "https://github.com/aws-samples/serverless-rust-demo")

The links below provide some great starting points for an API Gateway Authorizer

-   [https://github.com/aws-samples/aws-saas-factory-ref-solution-serverless-saas/blob/main/server/Resources/tenant_authorizer.py](https://github.com/aws-samples/aws-saas-factory-ref-solution-serverless-saas/blob/main/server/Resources/tenant_authorizer.py "https://github.com/aws-samples/aws-saas-factory-ref-solution-serverless-saas/blob/main/server/Resources/tenant_authorizer.py")
-   [https://github.com/awslabs/aws-apigateway-lambda-authorizer-blueprints/blob/master/blueprints/rust/main.rs](https://github.com/awslabs/aws-apigateway-lambda-authorizer-blueprints/blob/master/blueprints/rust/main.rs "https://github.com/awslabs/aws-apigateway-lambda-authorizer-blueprints/blob/master/blueprints/rust/main.rs")[https://github.com/awslabs/aws-apigateway-lambda-authorizer-blueprints/blob/master/blueprints/rust/main.rs](https://github.com/awslabs/aws-apigateway-lambda-authorizer-blueprints/blob/master/blueprints/rust/main.rs "https://github.com/awslabs/aws-apigateway-lambda-authorizer-blueprints/blob/master/blueprints/rust/main.rs")
