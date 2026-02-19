use proc_macro2::Span;
use quote::quote;
use syn::{Data, DeriveInput, Fields};

pub fn expand_metric_labels(input: DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let fields = match &input.data {
        Data::Struct(s) => match &s.fields {
            Fields::Named(f) => &f.named,
            _ => {
                return Err(syn::Error::new(
                    Span::call_site(),
                    "MetricLabels can only be derived for structs with named fields",
                ));
            }
        },
        _ => {
            return Err(syn::Error::new(
                Span::call_site(),
                "MetricLabels can only be derived for structs",
            ));
        }
    };

    let field_names: Vec<_> = fields.iter().map(|f| f.ident.as_ref().unwrap()).collect();

    let field_name_strs: Vec<_> = field_names.iter().map(|i| i.to_string()).collect();

    let field_types: Vec<_> = fields.iter().map(|f| &f.ty).collect();

    let struct_name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let where_predicates = field_types
        .iter()
        .map(|ty| quote!(#ty: ::std::string::ToString));

    Ok(quote! {
        impl #impl_generics MetricLabels for #struct_name #ty_generics
        where
            #(#where_predicates,)*
            #where_clause
        {
            fn labels(&self) -> impl AsRef<[(&'static str, ::std::string::String)]> {
                vec![
                    #( (#field_name_strs, self.#field_names.to_string()), )*
                ]
            }
        }
    })
}
