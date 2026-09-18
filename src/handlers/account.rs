//! Account device-list endpoints. Each version lives in its own module, so
//! retiring one means deleting its file and its line in [`routes`].

mod v0;
mod v1;

use std::sync::Arc;

use axum::Router;

use crate::store::Store;

pub(super) fn routes() -> Router<Arc<Store>> {
    Router::new().merge(v0::routes()).merge(v1::routes())
}
