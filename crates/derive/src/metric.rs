use proc_macro2::Span;
use quote::quote;
use syn::{DeriveInput, Meta, Path, punctuated::Punctuated, token::Comma};

enum MetricKind {
    Counter,
    Histogram,
    Gauge,
}

impl MetricKind {
    fn metric_type_tokens(&self) -> proc_macro2::TokenStream {
        match self {
            MetricKind::Counter => quote!(::metrics::Counter),
            MetricKind::Histogram => quote!(::metrics::Histogram),
            MetricKind::Gauge => quote!(::metrics::Gauge),
        }
    }
}

struct MetricArgs {
    kind: MetricKind,
    labels: Path,
    name: String,
}

pub fn expand_metric(input: DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let args = parse_metric_attr(&input)?;

    let struct_name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let metric_type = args.kind.metric_type_tokens();
    let labels_type = args.labels;
    let name = args.name;

    Ok(quote! {
        impl #impl_generics Metric for #struct_name #ty_generics #where_clause {
            type MetricType = #metric_type;
            type Labels = #labels_type;
            const NAME: &'static str = #name;
        }
    })
}

fn parse_metric_attr(input: &DeriveInput) -> syn::Result<MetricArgs> {
    let (attr, kind) = input
        .attrs
        .iter()
        .find_map(|a| {
            if a.path().is_ident("counter") {
                Some((a, MetricKind::Counter))
            } else if a.path().is_ident("histogram") {
                Some((a, MetricKind::Histogram))
            } else if a.path().is_ident("gauge") {
                Some((a, MetricKind::Gauge))
            } else {
                None
            }
        })
        .ok_or_else(|| {
            syn::Error::new(
                Span::call_site(),
                "missing kind attribute; add `#[counter(...)]`, `#[histogram(...)]`, or `#[gauge(...)]`",
            )
        })?;

    let nested = attr.parse_args_with(Punctuated::<Meta, Comma>::parse_terminated)?;

    let mut labels: Option<Path> = None;
    let mut name: Option<String> = None;

    for meta in &nested {
        match meta {
            Meta::NameValue(nv) if nv.path.is_ident("labels") => {
                labels = Some(crate::util::expr_to_path(&nv.value, "labels")?);
            }
            Meta::NameValue(nv) if nv.path.is_ident("name") => {
                name = Some(crate::util::expr_to_str(&nv.value, "name")?);
            }
            other => {
                return Err(syn::Error::new_spanned(
                    other,
                    "unknown argument; expected `labels = Type`, or `name = \"...\"`",
                ));
            }
        }
    }

    Ok(MetricArgs {
        kind,
        labels: labels
            .ok_or_else(|| syn::Error::new(Span::call_site(), "missing `labels = Type`"))?,
        name: name.ok_or_else(|| syn::Error::new(Span::call_site(), "missing `name = \"...\"`"))?,
    })
}
