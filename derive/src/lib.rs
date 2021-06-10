extern crate proc_macro;
#[macro_use]
extern crate quote;
extern crate syn;

use proc_macro::TokenStream;
use syn::Fields;

#[proc_macro_derive(Sequence)]
pub fn sequence_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse(input).unwrap();
    impl_sequence(&ast).into()
}

fn impl_sequence(ast: &syn::DeriveInput) -> proc_macro2::TokenStream {
    let name = &ast.ident;
    let (impl_generics, ty_generics, where_clause) = ast.generics.split_for_impl();

    if let syn::Data::Struct(data) = &ast.data {
        let fields = &data.fields;

        let mut write_asn1 = quote!();
        let mut read_asn1 = quote!();

        if let Fields::Named(named) = fields {
            for field in named.named.iter() {
                let name = field.ident.as_ref().unwrap();
                write_asn1.extend(quote! {
                    self.#name.write_asn1(sequence.next())?;
                });
                read_asn1.extend(quote! {
                    self.#name.read_asn1(sequence.next())?;
                });
            }
        }

        quote! {
            impl #impl_generics ASN1 for #name #ty_generics #where_clause {
                fn write_asn1(&self, writer: DERWriter) -> KerlabResult<()> {
                    writer.write_sequence(|sequence| -> KerlabResult<()> {
                        #write_asn1
                        Ok(())
                    })?;
                    Ok(())
                }

                fn read_asn1(&mut self, reader: BERReader) -> KerlabResult<()> {
                    reader.read_sequence(|sequence| {
                        #read_asn1
                        Ok(())
                    })?;
                    Ok(())
                }
            }
        }
    }
    else {
        panic!("error");
    }
}

#[proc_macro_derive(Component)]
pub fn component_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse(input).unwrap();
    impl_component(&ast).into()
}

fn impl_component(ast: &syn::DeriveInput) -> proc_macro2::TokenStream {
    let name = &ast.ident;
    let (impl_generics, ty_generics, where_clause) = ast.generics.split_for_impl();

    if let syn::Data::Struct(data) = &ast.data {
        let fields = &data.fields;

        let mut write_data = quote!();
        let mut read_data = quote!();

        if let Fields::Named(named) = fields {
            for field in named.named.iter() {
                let name = field.ident.as_ref().unwrap();
                write_data.extend(quote! {
                    self.#name.write(writer)?;
                });
                read_data.extend(quote! {
                    self.#name.read(reader)?;
                });
            }
        }

        quote! {
            impl #impl_generics Message for #name #ty_generics #where_clause {
                fn write(&self, writer: &mut dyn Write) -> KerlabResult<()> {
                    #write_data
                    Ok(())
                }

                fn read(&mut self, reader: &mut dyn Read) -> KerlabResult<()> {
                    #read_data
                    Ok(())
                }
            }
        }
    }
    else {
        panic!("error");
    }
}