use jsonrpsee::types::ErrorObjectOwned;
use jsonrpsee::types::error::{INTERNAL_ERROR_CODE, INTERNAL_ERROR_MSG, INVALID_PARAMS_CODE};

pub fn internal_error() -> ErrorObjectOwned {
    ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, INTERNAL_ERROR_MSG, None::<()>)
}

pub fn invalid_params_error(msg: &str) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(INVALID_PARAMS_CODE, msg, None::<()>)
}
