#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletStatus {
    Active,
    Suspended,
    Revoked,
}

impl std::str::FromStr for WalletStatus {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "active" => Ok(Self::Active),
            "suspended" => Ok(Self::Suspended),
            "revoked" => Ok(Self::Revoked),
            _ => Err(()),
        }
    }
}

pub const SCOPE_PAYMENT_READ: &str = "payment:read";
pub const SCOPE_GUARANTEE_ISSUE: &str = "guarantee:issue";
pub const DEFAULT_SCOPES: [&str; 1] = [SCOPE_PAYMENT_READ];

/// Legacy scope issued before the tab concept was removed; treated as
/// [`SCOPE_PAYMENT_READ`] on all ingress paths.
pub const SCOPE_TAB_READ_LEGACY: &str = "tab:read";

pub const ROLE_USER: &str = "user";
pub const ROLE_ADMIN: &str = "admin";
pub const ROLE_FACILITATOR: &str = "facilitator";
pub const DEFAULT_ROLE: &str = ROLE_USER;
