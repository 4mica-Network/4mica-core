use syn::{Expr, Lit, Path};

pub fn expr_to_path(expr: &Expr, field: &str) -> syn::Result<Path> {
    if let Expr::Path(ep) = expr {
        return Ok(ep.path.clone());
    }
    Err(syn::Error::new_spanned(
        expr,
        format!("`{field}` must be a type path"),
    ))
}

pub fn expr_to_str(expr: &Expr, field: &str) -> syn::Result<String> {
    if let Expr::Lit(el) = expr {
        if let Lit::Str(s) = &el.lit {
            return Ok(s.value());
        }
    }
    Err(syn::Error::new_spanned(
        expr,
        format!("`{field}` must be a string literal"),
    ))
}
