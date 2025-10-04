use crate::client::ClientCtx;

#[derive(Clone)]
pub struct UserClient {
    #[allow(unused)]
    ctx: ClientCtx,
}

impl UserClient {
    pub(super) fn new(ctx: ClientCtx) -> Self {
        Self { ctx }
    }
}
