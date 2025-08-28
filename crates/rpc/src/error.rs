use jsonrpsee::types::error::{
    CALL_EXECUTION_FAILED_CODE, INTERNAL_ERROR_CODE, INTERNAL_ERROR_MSG, INVALID_PARAMS_CODE,
};
use jsonrpsee::types::ErrorObjectOwned;

pub fn internal_error() -> ErrorObjectOwned {
    ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, INTERNAL_ERROR_MSG, None::<()>)
}

pub fn invalid_params_error(msg: &str) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(INVALID_PARAMS_CODE, msg, None::<()>)
}

pub fn execution_failed(msg: &str) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(CALL_EXECUTION_FAILED_CODE, msg, None::<()>)
}
