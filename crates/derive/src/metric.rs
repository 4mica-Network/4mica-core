use proc_macro2::Span;
use quote::quote;
use syn::{DeriveInput, Ident, LitStr, Token, Type, parse::ParseStream};

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

struct KindArgs {
    labels: Type,
    name: String,
}

impl syn::parse::Parse for KindArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut labels: Option<Type> = None;
        let mut name: Option<String> = None;

        while !input.is_empty() {
            let key: Ident = input.parse()?;
            let _: Token![=] = input.parse()?;

            if key == "labels" {
                labels = Some(input.parse()?);
            } else if key == "name" {
                name = Some(input.parse::<LitStr>()?.value());
            } else {
                return Err(syn::Error::new(
                    key.span(),
                    "unknown argument; expected `labels = Type` or `name = \"...\"`",
                ));
            }

            if input.peek(Token![,]) {
                let _: Token![,] = input.parse()?;
            }
        }

        Ok(KindArgs {
            labels: labels
                .ok_or_else(|| syn::Error::new(Span::call_site(), "missing `labels = Type`"))?,
            name: name
                .ok_or_else(|| syn::Error::new(Span::call_site(), "missing `name = \"...\"`"))?,
        })
    }
}

struct MetricArgs {
    kind: MetricKind,
    labels: Type,
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
        impl #impl_generics Metric<#metric_type> for #struct_name #ty_generics #where_clause {
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

    let KindArgs { labels, name } = attr.parse_args::<KindArgs>()?;

    Ok(MetricArgs { kind, labels, name })
}
