///! Built-in default templates using Askama
///!
///! All variables are HTML-escaped by default.
use askama::Template;

/// Minimal deny page, safe for unknown users.
/// You can replace it with your hotline or support page.
#[derive(Template)]
#[template(path = "./minimal-deny.html")]
struct DenyGeneric;

/// Default deny page, includes trace ID for support reference.
#[derive(Template)]
#[template(path = "./default-deny.html")]
struct DenyDefault {
    trace_id: uuid::Uuid,
}

pub fn render_builtin(name: &str) -> String {
    let trace_id = "";
    match name {
        "deny-default" => DenyDefault {
            trace_id
        }.render()
        .unwrap_or_else(|e| {
            tracing::warn!("Failed to render deny-default template: {e}");
            format!("Access Denied. Reference: {}", trace_id);
        }),

        _ => DenyGeneric.render().unwrap_or_else(|e| {
            tracing::warn!("Failed to render deny-generic template: {e}");
            "Access Denied".into()
        }
    }
}
