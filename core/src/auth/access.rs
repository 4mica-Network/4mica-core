use super::constants::{ROLE_ADMIN, ROLE_FACILITATOR};
use crate::error::{ServiceError, ServiceResult};
use entities::tabs;
use subtle::{Choice, ConstantTimeEq};

#[derive(Clone, Debug)]
pub struct AccessContext {
    pub wallet_address: String,
    pub role: String,
    pub scopes: Vec<String>,
}

pub fn scope_contains(scopes: &[String], required: &str) -> bool {
    let required_normalized = required.to_ascii_lowercase();
    let mut found = Choice::from(0u8);

    for scope in scopes {
        let scope_normalized = scope.trim().to_ascii_lowercase();
        found |= scope_normalized
            .as_bytes()
            .ct_eq(required_normalized.as_bytes());
    }

    bool::from(found)
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

pub fn require_recipient_match_or_facilitator(
    auth: &AccessContext,
    recipient_address: &str,
) -> ServiceResult<()> {
    if !addresses_match(&auth.wallet_address, recipient_address)
        && require_facilitator_role(auth).is_err()
    {
        return Err(ServiceError::Unauthorized(
            "recipient address does not match token subject and role is not facilitator".into(),
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

pub fn require_tab_owner_or_facilitator(
    auth: &AccessContext,
    tab: &tabs::Model,
) -> ServiceResult<()> {
    if addresses_match(&auth.wallet_address, &tab.user_address)
        || addresses_match(&auth.wallet_address, &tab.server_address)
        || require_facilitator_role(auth).is_ok()
    {
        return Ok(());
    }
    Err(ServiceError::Unauthorized(
        "tab access denied, must be owner or facilitator".into(),
    ))
}

pub fn require_admin_role(auth: &AccessContext) -> ServiceResult<()> {
    if !auth.role.trim().eq_ignore_ascii_case(ROLE_ADMIN) {
        return Err(ServiceError::Unauthorized("admin role required".into()));
    }
    Ok(())
}

pub fn require_facilitator_role(auth: &AccessContext) -> ServiceResult<()> {
    if !auth.role.trim().eq_ignore_ascii_case(ROLE_FACILITATOR) {
        return Err(ServiceError::Unauthorized(
            "facilitator role required".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::scope_contains;

    #[test]
    fn scope_contains_matches_case_insensitively() {
        let scopes = vec!["tab:read".to_string(), "Guarantee:Issue".to_string()];
        assert!(scope_contains(&scopes, "guarantee:issue"));
        assert!(scope_contains(&scopes, "TAB:READ"));
    }

    #[test]
    fn scope_contains_trims_scope_values() {
        let scopes = vec!["  tab:create  ".to_string()];
        assert!(scope_contains(&scopes, "tab:create"));
    }

    #[test]
    fn scope_contains_returns_false_for_missing_scope() {
        let scopes = vec!["tab:read".to_string()];
        assert!(!scope_contains(&scopes, "tab:create"));
    }
}
