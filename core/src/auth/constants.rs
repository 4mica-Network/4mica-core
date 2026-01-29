pub const WALLET_STATUS_ACTIVE: &str = "active";
pub const WALLET_STATUS_SUSPENDED: &str = "suspended";
pub const WALLET_STATUS_REVOKED: &str = "revoked";
pub const WALLET_STATUS_ALLOWED: [&str; 3] = [
    WALLET_STATUS_ACTIVE,
    WALLET_STATUS_SUSPENDED,
    WALLET_STATUS_REVOKED,
];

pub const SCOPE_TAB_CREATE: &str = "tab:create";
pub const SCOPE_TAB_READ: &str = "tab:read";
pub const SCOPE_GUARANTEE_ISSUE: &str = "guarantee:issue";
pub const DEFAULT_SCOPES: [&str; 1] = [SCOPE_TAB_READ];

pub const ROLE_USER: &str = "user";
pub const ROLE_ADMIN: &str = "admin";
pub const ROLE_FACILITATOR: &str = "facilitator";
pub const DEFAULT_ROLE: &str = ROLE_USER;
