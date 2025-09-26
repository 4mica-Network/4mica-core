use chrono::Utc;
use uuid::Uuid;

pub fn generate_unique_id() -> String {
    Uuid::new_v4().to_string()
}

pub fn now_naive() -> chrono::NaiveDateTime {
    Utc::now().naive_utc()
}
