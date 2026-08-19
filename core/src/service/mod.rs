//! Core service, split into three layers.
//!
//! - [`app`] — entrypoints: the composition root, the chain event handler, the scheduled tasks.
//! - [`domain`] — one service per area of behaviour, none depending on a sibling.
//! - [`shared`] — primitives the domain layer builds on, depending only on [`ctx::Ctx`],
//!   the repo layer, and the chain seam.
//!
//! Dependencies only ever point downwards, which is what keeps the graph acyclic.

pub mod app;
pub mod ctx;
pub mod domain;
pub mod shared;

pub use app::core::{CoreService, CoreServiceDeps};
pub use app::events::EventHandlerService;
pub use app::tasks::{SettlementCycleTask, ValidationLifecycleTask};
pub use ctx::Ctx;
