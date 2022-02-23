// Wrapper service around the AWS STS Client to allow for unit testing
use async_trait::async_trait;
use aws_sdk_sts::{model::Credentials, Client};
use lambda_runtime::Error;

#[async_trait]
pub trait STSService: Send + Sync {
    async fn get_tenant_session(
        &self,
        role_arn: &str,
        session_name: &str,
        iam_policy: &str,
    ) -> Result<Credentials, Error>;
}

pub struct STSClient {
    client: Client,
}

pub struct TestSTSClient {

}

impl STSClient {
    pub fn new(client: Client) -> STSClient {
        STSClient { client }
    }
}

#[async_trait]
impl STSService for STSClient {
    async fn get_tenant_session(
        &self,
        role_arn: &str,
        session_name: &str,
        iam_policy: &str,
    ) -> Result<Credentials, Error> {
        let assumed_role = self
            .client
            .assume_role()
            .role_arn(role_arn)
            .role_session_name(session_name)
            .policy(iam_policy.to_string())
            .send()
            .await;

        let credentials = match assumed_role {
            Ok(assumed_role) => assumed_role.credentials.unwrap(),
            Err(e) => {
                return Err(Box::new(simple_error::SimpleError::new(format!("{:?}", e))));
            }
        };

        return Ok(credentials);
    }
}

#[async_trait]
impl STSService for TestSTSClient {
    async fn get_tenant_session(
        &self,
        role_arn: &str,
        session_name: &str,
        iam_policy: &str,
    ) -> Result<Credentials, Error> {
        let _ = role_arn;
        let _ = session_name;
        let _ = iam_policy;

        let credentials = aws_sdk_sts::model::Credentials::builder()
        .access_key_id("testkeyid")
        .secret_access_key("testaccesskey")
        .session_token("testtoken").build();

        return Ok(credentials);
    }
}