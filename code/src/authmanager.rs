use lambda_runtime::Error;
use serde_json::{json, Value};

// These are the roles being supported in this reference architecture
pub enum UserRole {
    SystemAdmin,
    CustomerSupport,
    TenantAdmin,
    TenantUser,
}

pub fn is_tenant_admin(user_role: &UserRole) -> bool {
    match user_role {
        UserRole::TenantAdmin => return true,
        _ => return false,
    }
}

pub fn is_system_admin(user_role: &UserRole) -> bool {
    match user_role {
        UserRole::SystemAdmin => return true,
        _ => return false,
    }
}

pub fn is_saas_provider(user_role: &UserRole) -> bool {
    match user_role {
        UserRole::SystemAdmin => return true,
        UserRole::CustomerSupport => return true,
        _ => return false,
    }
}

pub fn is_tenant_user(user_role: &UserRole) -> bool {
    match user_role {
        UserRole::TenantUser => return true,
        _ => return false,
    }
}

pub fn get_policy_for_user(
    user_role: UserRole,
    tenant_id: &str,
    region: &str,
    aws_account_id: &str,
    env_name: &str,
) -> Result<Value, Error> {
    /* This method is being used by Authorizer to get appropriate policy by user role

    Args:
        user_role (string): UserRoles enum
        tenant_id (string):
        region (string):
        aws_account_id (string):

    Returns:
        string: policy that tenant needs to assume
    */
    let iam_policy: Value;

    if is_system_admin(&user_role) {
        iam_policy = get_policy_for_system_admin(region, aws_account_id, env_name);
    } else if is_tenant_admin(&user_role) {
        iam_policy = get_policy_for_tenant_admin(tenant_id, region, aws_account_id, env_name);
    } else if is_tenant_user(&user_role) {
        iam_policy = get_policy_for_tenant_user(tenant_id, region, aws_account_id, env_name);
    } else {
        // should never come here ??
        return Err(Box::new(simple_error::SimpleError::new(
            "Invalid user role mapping",
        )));
    }

    return Ok(iam_policy);
}

fn get_policy_for_system_admin(region: &str, aws_account_id: &str, env_name: &str) -> Value {
    let policy = json!({
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
                    format!("arn:aws:dynamodb:{0}:{1}:table/{2}-inventory*", region, aws_account_id, env_name),
                ]
            }
        ]
    });

    return policy;
}

fn get_policy_for_tenant_admin(
    tenant_id: &str,
    region: &str,
    aws_account_id: &str,
    env_name: &str,
) -> Value {
    let policy = json!({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "dynamodb:UpdateItem",
                    "dynamodb:GetItem",
                    "dynamodb:PutItem",
                    "dynamodb:DeleteItem",
                    "dynamodb:Query"
                ],
                "Resource": [
                    format!("arn:aws:dynamodb:{0}:{1}:table/{2}-inventory*", region, aws_account_id, env_name),
                ],
                "Condition": {
                    "ForAllValues:StringLike": {
                        "dynamodb:LeadingKeys": [
                            tenant_id
                        ]
                    }
                }
            }
        ]
    });

    return policy;
}

fn get_policy_for_tenant_user(
    tenant_id: &str,
    region: &str,
    aws_account_id: &str,
    env_name: &str,
) -> Value {
    let policy = json!({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "dynamodb:UpdateItem",
                    "dynamodb:GetItem",
                    "dynamodb:PutItem",
                    "dynamodb:DeleteItem",
                    "dynamodb:Query"
                ],
                "Resource": [
                    format!("arn:aws:dynamodb:{0}:{1}:table/{2}-inventory*", region, aws_account_id, env_name),
                ],
                "Condition": {
                    "ForAllValues:StringLike": {
                        "dynamodb:LeadingKeys": [
                            tenant_id
                        ]
                    }
                }
            }
        ]
    });

    return policy;
}
