use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet};
use jsonwebtoken::{decode, decode_header, jwk, Algorithm, DecodingKey, Validation};
use lambda_runtime::{handler_fn, Context, Error};
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tenant_authorizer::apigateway::{
    APIGatewayCustomAuthorizerRequest, APIGatewayCustomAuthorizerResponse, APIGatewayPolicyBuilder,
};
use tenant_authorizer::authmanager::{get_policy_for_user, UserRole};
use tenant_authorizer::stsservice::{STSClient, STSService};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    #[serde(rename = "custom:tenantId")]
    tenant_id: String,
    exp: usize,
    #[serde(rename = "cognito:username")]
    username: String,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        // this needs to be set to false, otherwise ANSI color codes will
        // show up in a confusing manner in CloudWatch logs.
        .with_ansi(false)
        // disabling time is handy because CloudWatch will add the ingestion time.
        .without_time()
        .json()
        .init();

    // Static Stuff

    info!("Init stuff should only happen once");

    let jwks_string = std::env::var("JWKS_STRING")
        .expect("A JWKS_STRING must be set in this app's Lambda environment variables.");

    let valid_issuers = std::env::var("VALID_ISSUERS")
        .expect("A VALID_ISSUERS must be set in this app's Lambda environment variables.");

    let env_name = std::env::var("ENV_NAME")
        .expect("A ENV_NAME must be set in this app's Lambda environment variables.");

    // Get AWS config
    let shared_config = aws_config::load_from_env().await;

    // STS Client Init
    let sts_client = aws_sdk_sts::Client::new(&shared_config);
    let sts_service = STSClient::new(sts_client);

    // Parsing JWKS and Issuer List
    let jwks_list: jwk::JwkSet = serde_json::from_str(&jwks_string).unwrap();
    let valid_issuers_array: [&str; 1] = serde_json::from_str(&valid_issuers).unwrap();

    // To support unit tests, allow override the expiary validation flag
    static VALIDATE_EXP: bool = true;

    lambda_runtime::run(handler_fn(
        |event: APIGatewayCustomAuthorizerRequest, ctx: Context| {
            debug!("Event: {}", json!(event));
            debug!("Context: {}", json!(ctx));
            auth_handler(
                &jwks_list,
                valid_issuers_array,
                &env_name,
                &sts_service,
                VALIDATE_EXP,
                event,
                ctx,
            )
        },
    ))
    .await?;
    Ok(())
}

// Seperate out the authentication logic
async fn auth_handler(
    jwks_list: &JwkSet,
    valid_issuers_array: [&str; 1],
    env_name: &str,
    sts_service: &dyn STSService,
    validate_exp: bool,
    event: APIGatewayCustomAuthorizerRequest,
    _ctx: Context,
) -> Result<APIGatewayCustomAuthorizerResponse, Error> {
    let request_raw_token = event.authorization_token;
    let request_method_arn = event.method_arn;

    debug!("Client token: {}", request_raw_token);
    debug!("Method ARN: {}", request_method_arn);

    let jwt_token;

    //let trace_id = ctx.xray_trace_id.split(";").collect::<Vec<&str>>()[0].split("=").collect::<Vec<&str>>()[1];

    // Basic token validation
    // make sure type is Bearer

    let token: Vec<&str> = request_raw_token.split(" ").collect();
    match token[0] {
        "Bearer" => {
            jwt_token = token[1];
        }

        _ => {
            debug!("Invalid Token Type (Not Bearer)");
            return Err(Box::new(simple_error::SimpleError::new("Unauthorized")));
        }
    }

    // Decode the header and find the kid
    let header = match decode_header(jwt_token) {
        Ok(header) => header,
        Err(e) => {
            return Err(unauthorized(&format!("Error decoding header {}", e)));
        }
    };

    let kid = match header.kid {
        Some(k) => k,
        None => {
            return Err(unauthorized("Token doesn't have a `kid` header field"));
        }
    };

    // Find the kid in the JWK list
    let jwk = match find_kid_in_key_list(&kid, jwks_list) {
        Ok(jwk) => jwk,
        Err(e) => {
            return Err(unauthorized(&format!("{}", e)));
        }
    };

    // Get the decode key and algorithm
    let (decoding_key, algorithm) = match get_decode_key_and_algorithm(jwk) {
        Ok((decoding_key, algorithm)) => (decoding_key, algorithm),
        Err(e) => {
            return Err(unauthorized(&format!("{}", e)));
        }
    };

    // Decode & Validate the token and retreive the claims
    let verified_claims = match decode_and_validate_token(
        jwt_token,
        decoding_key,
        algorithm,
        valid_issuers_array,
        validate_exp,
    ) {
        Ok(verified_claims) => verified_claims,
        Err(e) => {
            return Err(unauthorized(&format!("{}", e)));
        }
    };

    // if the token is valid, we assume client has access to tenant
    // At this point the token is considered valid

    // Assume allways called by user ?
    let principal_id = "User|".to_string() + &verified_claims.username;

    // keep in mind, the policy is cached for 5 minutes by default (TTL is configurable in the authorizer)
    // and will apply to subsequent calls to any method/resource in the RestApi
    // made with the same token

    //policy below allows access to all resources in the RestApi
    let tmp: Vec<&str> = request_method_arn.split(":").collect();
    let api_gateway_arn_tmp: Vec<&str> = tmp[5].split("/").collect();
    let aws_account_id = tmp[4];
    let region = tmp[3];
    let rest_api_id = api_gateway_arn_tmp[0];
    let api_stage = api_gateway_arn_tmp[1];

    let policy = APIGatewayPolicyBuilder::new(region, aws_account_id, rest_api_id, api_stage)
        .allow_all_methods()
        .build();

    //   Generate STS credentials to be used for FGAC

    //   Important Note:
    //   We are generating STS token inside Authorizer to take advantage of the caching behavior of authorizer

    let iam_policy = match get_policy_for_user(
        UserRole::TenantUser,
        &verified_claims.tenant_id,
        region,
        aws_account_id,
        env_name,
    ) {
        Ok(policy) => policy,
        Err(e) => {
            return Err(unauthorized(&format!("Policy Geeration Error {}", e)));
        }
    };

    let role_arn = format!(
        "arn:aws:iam::{0}:role/blueprint-rust-api-authorizer-access",
        aws_account_id
    );

    let credentials = match sts_service
        .get_tenant_session(&role_arn, "tenant-aware-session", &iam_policy.to_string())
        .await
    {
        Ok(tenant_session) => tenant_session,
        Err(e) => {
            return Err(unauthorized(&format!(
                "Error assuming tenant-aware-session {}",
                e
            )));
        }
    };

    // add additional key-value pairs associated with the authenticated principal
    // these are made available by APIGW like so: $context.authorizer.<key>
    // additional context is cached
    let response = APIGatewayCustomAuthorizerResponse {
        principal_id: principal_id.to_string(),
        policy_document: policy,
        context: json!({
        "userName": verified_claims.username,
        "tenantId": verified_claims.tenant_id,
        "accesskey": credentials.access_key_id,
        "secretkey" : credentials.secret_access_key,
        "sessiontoken" : credentials.session_token,
        }),
    };
    debug!("Response: {}", json!(response));
    Ok(response)
}

// Method to find Decoding key and Algorithm from a JWK
fn get_decode_key_and_algorithm(jwk: Jwk) -> Result<(DecodingKey, Algorithm), Error> {
    // Check the algo - we only support RSA
    match jwk.algorithm {
        AlgorithmParameters::RSA(ref rsa) => {
            // Setup the decode key
            let decoding_key = DecodingKey::from_rsa_components(&rsa.n, &rsa.e).unwrap();

            return Ok((decoding_key, jwk.common.algorithm.unwrap()));
        }
        _ => unreachable!("We only support RSA"),
    }
}

// Find a key from a JwkSet using a kid
fn find_kid_in_key_list(kid: &str, jwk_list: &JwkSet) -> Result<Jwk, Error> {
    // Find the kid in the JWK list
    if let Some(j) = jwk_list.find(kid) {
        return Ok(j.clone());
    } else {
        return Err(Box::new(simple_error::SimpleError::new(
            "No matching JWK found for the given kid)",
        )));
    }
}

// Use the rust jsonwebtoken crate to decode and validate a jwt token
fn decode_and_validate_token(
    jwt_token: &str,
    decoding_key: DecodingKey,
    algorithm: Algorithm,
    valid_issuers_array: [&str; 1],
    validate_exp: bool,
) -> Result<Claims, Error> {
    // Setup validations
    // Explicitely set the ones we want
    // @Issuer - Make sure only our list of accepted issuers
    // @Expiery - Make sure the token hasnt expired
    let mut validation = Validation::new(algorithm);
    validation.validate_exp = validate_exp;
    validation.set_issuer(&valid_issuers_array);

    // Decode and validate the token
    // Assumption is that resulting claims are verified
    // If there is a validation error the lib throws and excecption
    let decoded_token = decode::<Claims>(jwt_token, &decoding_key, &validation)?;

    return Ok(decoded_token.claims);
}

// Helper function to log an error and throw "Unauthorized" instead, API Gateway intercepts 
// any errors other than Unauthrized to prevent attacks
fn unauthorized(log_msg: &str) -> Error {
    error!("{}", log_msg);
    return Box::new(simple_error::SimpleError::new("Unauthorized"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderMap, HeaderValue};
    use tenant_authorizer::{
        stsservice::TestSTSClient,
    };
    use spectral::prelude::*;

    static TEST_STS_CLIENT: TestSTSClient = TestSTSClient {};

    fn get_valid_jwk_rsa() -> jwk::JwkSet {
        return serde_json::from_str(&r#"{
            "keys": [
              {
                "kty": "RSA",
                "n": "6S7asUuzq5Q_3U9rbs-PkDVIdjgmtgWreG5qWPsC9xXZKiMV1AiV9LXyqQsAYpCqEDM3XbfmZqGb48yLhb_XqZaKgSYaC_h2DjM7lgrIQAp9902Rr8fUmLN2ivr5tnLxUUOnMOc2SQtr9dgzTONYW5Zu3PwyvAWk5D6ueIUhLtYzpcB-etoNdL3Ir2746KIy_VUsDwAM7dhrqSK8U2xFCGlau4ikOTtvzDownAMHMrfE7q1B6WZQDAQlBmxRQsyKln5DIsKv6xauNsHRgBAKctUxZG8M4QJIx3S6Aughd3RZC4Ca5Ae9fd8L8mlNYBCrQhOZ7dS0f4at4arlLcajtw",
                "e": "AQAB",
                "kid": "test-rsa",
                "alg":"RS256"
              }
            ]
          }"#).unwrap();
    }

    fn get_valid_issuer_list() -> [&'static str; 1] {
        return serde_json::from_str(
            &r#"["https://cognito-idp.ap-southeast-2.amazonaws.com/yyyy-xxxx"]"#,
        )
        .unwrap();
    }

    fn get_valid_context() -> Context {
        let mut headers = HeaderMap::new();
        headers.insert(
            "lambda-runtime-aws-request-id",
            HeaderValue::from_static("my-id"),
        );
        headers.insert(
            "lambda-runtime-deadline-ms",
            HeaderValue::from_static("123"),
        );
        headers.insert(
            "lambda-runtime-invoked-function-arn",
            HeaderValue::from_static("arn::myarn"),
        );
        headers.insert(
            "lambda-runtime-trace-id",
            HeaderValue::from_static("traceid"),
        );
        return Context::try_from(headers).unwrap();
    }

    #[tokio::test]
    async fn test_auth_handler_where_valid_token_returns_auth_success() -> Result<(), Error> {
        // For this test we need to disable token expiary validation as we will never be able to hard code a test token that will never expire
        let this_validate_exp = false;

        // Generate a new valid token with the following claims
        // {
        //     "origin_jti": "b0661df2-26f1-471d-9080-8410743c90da",
        //     "custom:tenantId": "1234567xyz",
        //     "sub": "d1fdf006-3e99-415e-984e-b649beb2212f",
        //     "aud": "28iqrgirmnh3vc2dpldg4h19n",
        //     "event_id": "f0bbddfd-564f-4268-94b7-2b0e64f57d51",
        //     "token_use": "id",
        //     "auth_time": 1644823894,
        //     "iss": "https://cognito-idp.ap-southeast-2.amazonaws.com/yyyy-xxxx",
        //     "cognito:username": "niro.am",
        //     "exp": 1645391153,
        //     "iat": 1645474285,
        //     "jti": "e429cdc2-da3a-4bbb-8ac0-b9198e802f39"
        //   }
        //

        // setup valid jwk and issuer to match token signature
        let valid_jwk_list = get_valid_jwk_rsa();
        let valid_issuers_array = get_valid_issuer_list();
        let valid_ctx = get_valid_context();

        let test_event = APIGatewayCustomAuthorizerRequest {
            _type: "TOKEN".to_string(),
            authorization_token: "Bearer eyJraWQiOiJ0ZXN0LXJzYSIsImFsZyI6IlJTMjU2In0.eyJvcmlnaW5fanRpIjoiYjA2NjFkZjItMjZmMS00NzFkLTkwODAtODQxMDc0M2M5MGRhIiwiY3VzdG9tOnRlbmFudElkIjoiMTIzNDU2N3h5eiIsInN1YiI6ImQxZmRmMDA2LTNlOTktNDE1ZS05ODRlLWI2NDliZWIyMjEyZiIsImF1ZCI6IjI4aXFyZ2lybW5oM3ZjMmRwbGRnNGgxOW4iLCJldmVudF9pZCI6ImYwYmJkZGZkLTU2NGYtNDI2OC05NGI3LTJiMGU2NGY1N2Q1MSIsInRva2VuX3VzZSI6ImlkIiwiYXV0aF90aW1lIjoxNjQ0ODIzODk0LCJpc3MiOiJodHRwczovL2NvZ25pdG8taWRwLmFwLXNvdXRoZWFzdC0yLmFtYXpvbmF3cy5jb20veXl5eS14eHh4IiwiY29nbml0bzp1c2VybmFtZSI6Im5pcm8uYW0iLCJleHAiOjE2NDUzOTExNTMsImlhdCI6MTY0NTQ3NDI4NSwianRpIjoiZTQyOWNkYzItZGEzYS00YmJiLThhYzAtYjkxOThlODAyZjM5In0.2UiUgopWyuvy1QK0f56HwZ9mZoF781Gf4IWO7pj_PHN0jdm1_uZt8JhQ4qmFY4Qfng8Yr14AEyf9oGhJte9FBSZWUzOyJ_w9smrWpZc_p49K6HDYfNoNEHhZ0HIRhR6IfKwqZCdQbK0S5L020QjzLN7RlxvwVfmzRMU-3veSfkQVRHJaFkW-djmf4xB4o-Kqvl9p0PBC5pMwAT-43A8rXQ1RV4BaTFMB2OpAe6vqoFxLc5jXIMEG18ehe6-c4fjJsWA131G91Xxe_alUd5uYNzAZWzz5JJYj3uigW-iml6Wnf82aEQzmScRt1PRr1UlkBcvcpnZ35DOp7KSNE7AjpQ".to_string(),
            method_arn: "arn:aws:execute-api:us-east-1:123456789012:example/prod/POST/{proxy+}".to_string()
        };

        let actual_response = auth_handler(
            &valid_jwk_list,
            valid_issuers_array,
            "unittest",
            &TEST_STS_CLIENT,
            this_validate_exp,
            test_event,
            valid_ctx,
        )
        .await;

        let expected_response: APIGatewayCustomAuthorizerResponse = serde_json::from_str(
            r#"
        {
            "context":{
                "accesskey":"testkeyid",
                "secretkey":"testaccesskey",
                "sessiontoken":"testtoken",
                "tenantId":"1234567xyz",
                "userName":"niro.am"
            },
            "policyDocument":{
                "Statement":[
                    {
                    "Action":[
                        "execute-api:Invoke"
                        ],
                        "Effect":"Allow",
                        "Resource":[
                            "arn:aws:execute-api:us-east-1:123456789012:example/prod/*/*"
                            ]
                        }
                        ],
                    "Version":"2012-10-17"
                },
                "principalId":"User|niro.am"
            }"#,
        )
        .unwrap();

        assert_that!(actual_response).is_ok().is_equal_to(expected_response);

        Ok(())
    }

    #[tokio::test]
    async fn test_auth_handler_where_expired_token_returns_auth_fail() -> Result<(), Error> {
        // For this test we need to keep the expiary validation turned on
        let this_validate_exp = true;

        // Generate a new valid token with the following claims
        // {
        //     "origin_jti": "b0661df2-26f1-471d-9080-8410743c90da",
        //     "custom:tenantId": "1234567xyz",
        //     "sub": "d1fdf006-3e99-415e-984e-b649beb2212f",
        //     "aud": "28iqrgirmnh3vc2dpldg4h19n",
        //     "event_id": "f0bbddfd-564f-4268-94b7-2b0e64f57d51",
        //     "token_use": "id",
        //     "auth_time": 1644823894,
        //     "iss": "https://cognito-idp.ap-southeast-2.amazonaws.com/yyyy-xxxx",
        //     "cognito:username": "niro.am",
        //     "exp": 1645391153,
        //     "iat": 1645474285,
        //     "jti": "e429cdc2-da3a-4bbb-8ac0-b9198e802f39"
        //   }
        //

        // setup valid jwk and issuer to match token signature
        let valid_jwk_list = get_valid_jwk_rsa();
        let valid_issuers_array = get_valid_issuer_list();
        let valid_ctx = get_valid_context();

        let test_event = APIGatewayCustomAuthorizerRequest {
            _type: "TOKEN".to_string(),
            authorization_token: "Bearer eyJraWQiOiJ0ZXN0LXJzYSIsImFsZyI6IlJTMjU2In0.eyJvcmlnaW5fanRpIjoiYjA2NjFkZjItMjZmMS00NzFkLTkwODAtODQxMDc0M2M5MGRhIiwiY3VzdG9tOnRlbmFudElkIjoiMTIzNDU2N3h5eiIsInN1YiI6ImQxZmRmMDA2LTNlOTktNDE1ZS05ODRlLWI2NDliZWIyMjEyZiIsImF1ZCI6IjI4aXFyZ2lybW5oM3ZjMmRwbGRnNGgxOW4iLCJldmVudF9pZCI6ImYwYmJkZGZkLTU2NGYtNDI2OC05NGI3LTJiMGU2NGY1N2Q1MSIsInRva2VuX3VzZSI6ImlkIiwiYXV0aF90aW1lIjoxNjQ0ODIzODk0LCJpc3MiOiJodHRwczovL2NvZ25pdG8taWRwLmFwLXNvdXRoZWFzdC0yLmFtYXpvbmF3cy5jb20veXl5eS14eHh4IiwiY29nbml0bzp1c2VybmFtZSI6Im5pcm8uYW0iLCJleHAiOjE2NDUzOTExNTMsImlhdCI6MTY0NTQ3NDI4NSwianRpIjoiZTQyOWNkYzItZGEzYS00YmJiLThhYzAtYjkxOThlODAyZjM5In0.2UiUgopWyuvy1QK0f56HwZ9mZoF781Gf4IWO7pj_PHN0jdm1_uZt8JhQ4qmFY4Qfng8Yr14AEyf9oGhJte9FBSZWUzOyJ_w9smrWpZc_p49K6HDYfNoNEHhZ0HIRhR6IfKwqZCdQbK0S5L020QjzLN7RlxvwVfmzRMU-3veSfkQVRHJaFkW-djmf4xB4o-Kqvl9p0PBC5pMwAT-43A8rXQ1RV4BaTFMB2OpAe6vqoFxLc5jXIMEG18ehe6-c4fjJsWA131G91Xxe_alUd5uYNzAZWzz5JJYj3uigW-iml6Wnf82aEQzmScRt1PRr1UlkBcvcpnZ35DOp7KSNE7AjpQ".to_string(),
            method_arn: "arn:aws:execute-api:us-east-1:123456789012:example/prod/POST/{proxy+}".to_string()
        };

        let actual_response = auth_handler(
            &valid_jwk_list,
            valid_issuers_array,
            "unittest",
            &TEST_STS_CLIENT,
            this_validate_exp,
            test_event,
            valid_ctx,
        )
        .await;

        assert_that!(actual_response).is_err();

        Ok(())
    }

    #[tokio::test]
    async fn test_auth_handler_where_token_with_invalid_issuer_returns_auth_fail() -> Result<(), Error> {
        // For this test we need to keep the expiary validation turned off
        // to ensure tested faliure is on the target criter
        let this_validate_exp = false;

        // Generate a new valid token with the following claims
        // {
        //     "origin_jti": "b0661df2-26f1-471d-9080-8410743c90da",
        //     "custom:tenantId": "1234567xyz",
        //     "sub": "d1fdf006-3e99-415e-984e-b649beb2212f",
        //     "aud": "28iqrgirmnh3vc2dpldg4h19n",
        //     "event_id": "f0bbddfd-564f-4268-94b7-2b0e64f57d51",
        //     "token_use": "id",
        //     "auth_time": 1644823894,
        //     "iss": "https://blah.com/yyyy-xxxx", <------------------------ INVALID ISSUER
        //     "cognito:username": "niro.am",
        //     "exp": 1645391153,
        //     "iat": 1645474285,
        //     "jti": "e429cdc2-da3a-4bbb-8ac0-b9198e802f39"
        //   }
        //

        // setup valid jwk and issuer to match token signature
        let valid_jwk_list = get_valid_jwk_rsa();
        let valid_issuers_array = get_valid_issuer_list();
        let valid_ctx = get_valid_context();

        let test_event = APIGatewayCustomAuthorizerRequest {
            _type: "TOKEN".to_string(),
            authorization_token: "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InRlc3QtcnNhIn0.eyJvcmlnaW5fanRpIjoiYjA2NjFkZjItMjZmMS00NzFkLTkwODAtODQxMDc0M2M5MGRhIiwiY3VzdG9tOnRlbmFudElkIjoiMTIzNDU2N3h5eiIsInN1YiI6ImQxZmRmMDA2LTNlOTktNDE1ZS05ODRlLWI2NDliZWIyMjEyZiIsImF1ZCI6IjI4aXFyZ2lybW5oM3ZjMmRwbGRnNGgxOW4iLCJldmVudF9pZCI6ImYwYmJkZGZkLTU2NGYtNDI2OC05NGI3LTJiMGU2NGY1N2Q1MSIsInRva2VuX3VzZSI6ImlkIiwiYXV0aF90aW1lIjoxNjQ0ODIzODk0LCJpc3MiOiJodHRwczovL2JsYWguY29tL3l5eXkteHh4eCIsImNvZ25pdG86dXNlcm5hbWUiOiJuaXJvLmFtIiwiZXhwIjoxNjQ1MzkxMTUzLCJpYXQiOjE2NDU0NzQyODV9.zZzdsGSVMMmAYEFnR9J35bKkm-ecMI_HMcxG41TfdeJ-9CF9xiJPbMNlV0d_-DDlTVw1p1Cwj6vp7HsedqeidihDKT436orbFrjlPMyhkuNYPfNYmZ2iGWVgwTfFj8N5QDMjC7IJfildbP4R3iGRx9iNZ29GnFVxSC_tchMOiKPvpcB4rMQ5Exwasqy0-xT_H80Z2XSQakrDDQdy4-yzeWi0YqO3yxbnmwl9mzHSrSRig8RRdUy7MDDJPhAfFU9dWiv7Pa3t9ArfMWy6CuPE-B9MBeF12HcBWdVZqPD2eFMlBZm9LizfXiga7CqE1obLzmlVpabWRzCmFdQC8wYqAw".to_string(),
            method_arn: "arn:aws:execute-api:us-east-1:123456789012:example/prod/POST/{proxy+}".to_string()
        };

        let actual_response = auth_handler(
            &valid_jwk_list,
            valid_issuers_array,
            "unittest",
            &TEST_STS_CLIENT,
            this_validate_exp,
            test_event,
            valid_ctx,
        )
        .await;

        assert_that!(actual_response).is_err();

        Ok(())
    }

    #[tokio::test]
    async fn test_auth_handler_where_token_with_invalid_kid_returns_auth_fail() -> Result<(), Error> {
        // For this test we need to keep the expiary validation turned off
        // to ensure tested faliure is on the target criter
        let this_validate_exp = false;

        // Generate a new valid token with and invalid header as follows
        // {
        //     "typ": "JWT",
        //     "alg": "RS256",
        //     "kid": "test-badkey"
        //   }

        // setup valid jwk and issuer to match token signature
        let valid_jwk_list = get_valid_jwk_rsa();
        let valid_issuers_array = get_valid_issuer_list();
        let valid_ctx = get_valid_context();

        let test_event = APIGatewayCustomAuthorizerRequest {
            _type: "TOKEN".to_string(),
            authorization_token: "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InRlc3QtYmFka2V5In0.eyJvcmlnaW5fanRpIjoiYjA2NjFkZjItMjZmMS00NzFkLTkwODAtODQxMDc0M2M5MGRhIiwiY3VzdG9tOnRlbmFudElkIjoiMTIzNDU2N3h5eiIsInN1YiI6ImQxZmRmMDA2LTNlOTktNDE1ZS05ODRlLWI2NDliZWIyMjEyZiIsImF1ZCI6IjI4aXFyZ2lybW5oM3ZjMmRwbGRnNGgxOW4iLCJldmVudF9pZCI6ImYwYmJkZGZkLTU2NGYtNDI2OC05NGI3LTJiMGU2NGY1N2Q1MSIsInRva2VuX3VzZSI6ImlkIiwiYXV0aF90aW1lIjoxNjQ0ODIzODk0LCJpc3MiOiJodHRwczovL2JsYWguY29tL3l5eXkteHh4eCIsImNvZ25pdG86dXNlcm5hbWUiOiJuaXJvLmFtIiwiZXhwIjoxNjQ1MzkxMTUzLCJpYXQiOjE2NDU0NzQyODV9.TLLDV3h7LxbUHNQFwSPOT19nmFyqr75cp0tVvmt4WK98jE4x2uKm9E5h5H9vineuhzKAFi0gK21itgK9fVkaQpP9ULIGdrtwRKITQXto0EZ93ZA1koloMsebhgcSp2aJm28HRdLgvsVTDxEvSZF9tnK9eeMrCgAbUinJ68tPi3UcYCN4cuTIyCc24G3d9ppD9ktycqPT6BeMhiEpTiBXCvaFr9oOSQxvSxwDxAVYBNkY-0xJpWlz-eM-636xtEVHaD3s5t8TZwU2sh4uYiT9_i1rfxkfBzpUrhejAaR7nYL3yAOFgU8B_RU5V7K0TQC8bGrB9-1AfNnfizuy7tS5fA".to_string(),
            method_arn: "arn:aws:execute-api:us-east-1:123456789012:example/prod/POST/{proxy+}".to_string()
        };

        let actual_response = auth_handler(
            &valid_jwk_list,
            valid_issuers_array,
            "unittest",
            &TEST_STS_CLIENT,
            this_validate_exp,
            test_event,
            valid_ctx,
        )
        .await;

        assert_that!(actual_response).is_err();

        Ok(())
    }

    #[tokio::test]
    async fn test_auth_handler_where_injected_claims_returns_auth_fail() -> Result<(), Error> {
        // For this test we need to keep the expiary validation turned off
        // to ensure tested faliure is on the target criter
        let this_validate_exp = false;

        // Generate a new invalid token with injected claims
        // {
        //     "origin_jti": "b0661df2-26f1-471d-9080-8410743c90da",
        //     "custom:tenantId": "admin",    <------------------------- Injected a different claim value
        //     "sub": "d1fdf006-3e99-415e-984e-b649beb2212f",
        //     "aud": "28iqrgirmnh3vc2dpldg4h19n",
        //     "event_id": "f0bbddfd-564f-4268-94b7-2b0e64f57d51",
        //     "token_use": "id",
        //     "auth_time": 1644823894,
        //     "iss": "https://cognito-idp.ap-southeast-2.amazonaws.com/yyyy-xxxx",
        //     "cognito:username": "niro.am",
        //     "exp": 1645391153,
        //     "iat": 1645474285,
        //     "jti": "e429cdc2-da3a-4bbb-8ac0-b9198e802f39"
        //   }
        //

        // setup valid jwk and issuer to match token signature
        let valid_jwk_list = get_valid_jwk_rsa();
        let valid_issuers_array = get_valid_issuer_list();
        let valid_ctx = get_valid_context();

        let test_event = APIGatewayCustomAuthorizerRequest {
            _type: "TOKEN".to_string(),
            authorization_token: "Bearer eyJraWQiOiJ0ZXN0LXJzYSIsImFsZyI6IlJTMjU2IiwiandrIjp7Imt0eSI6IlJTQSIsImtpZCI6Imp3dF90b29sIiwidXNlIjoic2lnIiwiZSI6IkFRQUIiLCJuIjoid0hkM1lVaUYwOVhWOUtqQk9ObGhUV2hlY0l1OUt4ZlFhNlF6OTZISFV5S0l2QWhOQ0tra1hzXzlHMGNOS0d4QlNQZm1kWjlUdHNjYVF1S3ZQQjBFc19PSWlXMG1FYkNJODJLSUJVNXpaZ3BWTXFIczlJNllzSjBWZHRKNjVFbGs2bHFzaGQtVGNBYzJ6VDBETUNwTUxBOHdVOXRpOEl3RzVGY253Q1VGYS1tQkhNb0hGcE53RzFwcG04aGNWTXRvclIyQWZqNEdoMV92SGotMUxqNWJPNFlibFl1RERKdF9aYmU1X20zYS03NjVfY29Md183enRhclpOa1JoSlZBOXlmeGp5Wm5NNWRYTGhIU3dFU2xrZXA2SG5WTFBpSFZvbWU4ZWsyZERZeDQtYlJzdFBPTFpKSGM5U3NyNGM5TG9RM1JVcHJGbzhyalRXX21JZm9QNmt3In19.eyJvcmlnaW5fanRpIjoiYjA2NjFkZjItMjZmMS00NzFkLTkwODAtODQxMDc0M2M5MGRhIiwiY3VzdG9tOnRlbmFudElkIjoiYWRtaW4iLCJzdWIiOiJkMWZkZjAwNi0zZTk5LTQxNWUtOTg0ZS1iNjQ5YmViMjIxMmYiLCJhdWQiOiIyOGlxcmdpcm1uaDN2YzJkcGxkZzRoMTluIiwiZXZlbnRfaWQiOiJmMGJiZGRmZC01NjRmLTQyNjgtOTRiNy0yYjBlNjRmNTdkNTEiLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTY0NDgyMzg5NCwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC5hcC1zb3V0aGVhc3QtMi5hbWF6b25hd3MuY29tL3l5eXkteHh4eCIsImNvZ25pdG86dXNlcm5hbWUiOiJuaXJvLmFtIiwiZXhwIjoxNjQ1MzkxMTUzLCJpYXQiOjE2NDU0NzQyODUsImp0aSI6ImU0MjljZGMyLWRhM2EtNGJiYi04YWMwLWI5MTk4ZTgwMmYzOSJ9.JwgGC8mESiQ5Q8ml8iNA8VVVsHCaEKeXmB39wrILPEBOXqefkwfS-Iy4w-DMRmUBxiGXZ4eVe3NUr8O_L4lk1IdkyNeVEz0oSNyUdkjbsBfFWLaTVVbGeH18KAtlJGdnMFvUDnVJLt0T56joIP98NHxWij0mouOqozR4DZ7GjV6RBps5vxGjOg1kopJnZuiJELrWpJYli69193qHs384hdsgvv3t6e1jFO9FxLGXSBneWDf06pd-q_TZMm6FmOcGybwHbo2gaAj6fZv4xr5bwCvYxQEAyqq_zEJWz1br2IqXyLPdYdIYxM6jet_DI_4QVjJHTt0ziA9av4pdXChoLA".to_string(),
            method_arn: "arn:aws:execute-api:us-east-1:123456789012:example/prod/POST/{proxy+}".to_string()
        };

        let actual_response = auth_handler(
            &valid_jwk_list,
            valid_issuers_array,
            "unittest",
            &TEST_STS_CLIENT,
            this_validate_exp,
            test_event,
            valid_ctx,
        )
        .await;

        assert_that!(actual_response).is_err();

        Ok(())
    }
}
