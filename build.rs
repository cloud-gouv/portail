fn main() {
    let out = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let out_path = std::path::Path::new(&out)
        .join("locale")
        .join("translators.rs");

    include_po::generate_locales_from_dir("locales", out_path)
        .expect("Failed to generate locale catalog from locales/*.po");
}
