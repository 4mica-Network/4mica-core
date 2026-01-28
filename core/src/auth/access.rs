use crate::error::{ServiceError, ServiceResult};
use entities::tabs;

#[derive(Clone, Debug)]
pub struct AccessContext {
    pub wallet_address: String,
    pub role: String,
    pub scopes: Vec<String>,
}

pub fn scope_contains(scopes: &[String], required: &str) -> bool {
    scopes
        .iter()
        .any(|scope| scope.trim().eq_ignore_ascii_case(required))
}

pub fn addresses_match(left: &str, right: &str) -> bool {
    left.trim().eq_ignore_ascii_case(right.trim())
}

pub fn require_scope(auth: &AccessContext, scope: &str) -> ServiceResult<()> {
    if !scope_contains(&auth.scopes, scope) {
        return Err(ServiceError::Unauthorized("missing scope".into()));
    }
    Ok(())
}

pub fn require_recipient_match(auth: &AccessContext, recipient_address: &str) -> ServiceResult<()> {
    if !addresses_match(&auth.wallet_address, recipient_address) {
        return Err(ServiceError::Unauthorized(
            "recipient address does not match token subject".into(),
        ));
    }
    Ok(())
}

pub fn require_user_match(auth: &AccessContext, user_address: &str) -> ServiceResult<()> {
    if !addresses_match(&auth.wallet_address, user_address) {
        return Err(ServiceError::Unauthorized(
            "user address does not match token subject".into(),
        ));
    }
    Ok(())
}

pub fn require_tab_owner(auth: &AccessContext, tab: &tabs::Model) -> ServiceResult<()> {
    if addresses_match(&auth.wallet_address, &tab.user_address)
        || addresses_match(&auth.wallet_address, &tab.server_address)
    {
        return Ok(());
    }
    Err(ServiceError::Unauthorized("tab access denied".into()))
}

pub fn require_admin_role(auth: &AccessContext) -> ServiceResult<()> {
    if !auth.role.trim().eq_ignore_ascii_case("admin") {
        return Err(ServiceError::Unauthorized("admin role required".into()));
    }
    Ok(())
}
