//! Application entrypoints: the composition root, the chain event handler, and the scheduled
//! tasks. These may depend on any domain service; nothing depends on them.

pub mod core;
pub mod events;
pub mod tasks;

use std::sync::Arc;

use crate::config::EthereumConfig;
use crate::ethereum::EthereumEventScanner;
use core::CoreService;
use events::EventHandlerService;

/// Wire a chain event scanner onto a running service.
pub fn event_scanner(config: EthereumConfig, service: &CoreService) -> EthereumEventScanner {
    EthereumEventScanner::new(
        config,
        service.persist_ctx().clone(),
        service.read_provider().clone(),
        Arc::new(EventHandlerService::new(
            service.ctx().clone(),
            service.clearing().clone(),
        )),
    )
}
