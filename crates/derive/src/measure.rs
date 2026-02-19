use proc_macro2::TokenStream;
use quote::quote;
use syn::{ItemFn, Path, parse::ParseStream};

struct MeasureArgs {
    report_fn: Path,
}

impl syn::parse::Parse for MeasureArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let report_fn: Path = input.parse()?;
        Ok(MeasureArgs { report_fn })
    }
}

pub fn expand_measure(args: TokenStream, input: TokenStream) -> syn::Result<TokenStream> {
    let MeasureArgs { report_fn } = syn::parse2(args)?;
    let func: ItemFn = syn::parse2(input)?;

    let fn_name = func.sig.ident.to_string();
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
                name: #fn_name,
                start: ::std::time::Instant::now(),
                report: #report_fn,
            };

            #block
        }
    })
}
