use proc_macro2::TokenStream;
use quote::quote;
use syn::{Ident, ItemFn, LitStr, Path, parse::ParseStream, token::Comma};

struct MeasureArgs {
    report_fn: Path,
    name: Option<LitStr>,
}

impl syn::parse::Parse for MeasureArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let report_fn: Path = input.parse()?;
        let mut name: Option<LitStr> = None;

        if !input.is_empty() {
            input.parse::<Comma>()?;
            let key: Ident = input.parse()?;
            if key == "name" {
                input.parse::<syn::token::Eq>()?;
                name = Some(input.parse()?);
            } else {
                return Err(syn::Error::new(
                    key.span(),
                    "unknown attribute; expected `name`",
                ));
            }
        }

        Ok(MeasureArgs { report_fn, name })
    }
}

pub fn expand_measure(args: TokenStream, input: TokenStream) -> syn::Result<TokenStream> {
    let MeasureArgs { report_fn, name } = syn::parse2(args)?;
    let func: ItemFn = syn::parse2(input)?;

    let name_lit = name.unwrap_or_else(|| {
        syn::LitStr::new(&func.sig.ident.to_string(), proc_macro2::Span::call_site())
    });
    let vis = &func.vis;
    let sig = &func.sig;
    let block = &func.block;
    let attrs = &func.attrs;

    Ok(quote! {
        #(#attrs)*
        #vis #sig {
            // Using guard pattern to handle early returns and panics.
            struct __MeasureGuard<F: ::std::ops::Fn(&'static str, ::std::time::Duration)> {
                name: &'static str,
                start: ::std::time::Instant,
                report: F,
            }

            impl<F: ::std::ops::Fn(&'static str, ::std::time::Duration)> ::std::ops::Drop
                for __MeasureGuard<F>
            {
                fn drop(&mut self) {
                    (self.report)(self.name, self.start.elapsed());
                }
            }

            let _guard = __MeasureGuard {
                name: #name_lit,
                start: ::std::time::Instant::now(),
                report: #report_fn,
            };

            #block
        }
    })
}
