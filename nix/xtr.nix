{ lib, rustPlatform, fetchCrate }:

rustPlatform.buildRustPackage rec {
  pname = "xtr";
  version = "0.1.11";

  src = fetchCrate {
    inherit pname version;
    hash = "sha256-ouuctuXZp97OWfM8IfJUMG9WdVji6WCGD2L5mXWHs/I=";
  };

  cargoHash = "sha256-1nqFGYbW8d4I+H2yyD/cyUE0UmYpYgy5pQ/0aDKpP5w=";

  strictDeps = true;

  meta = {
    description = "Extract strings from a Rust crate to be translated with gettext (xgettext for Rust)";
    homepage = "https://github.com/woboq/tr";
    license = lib.licenses.agpl3Only;
    maintainers = with lib.maintainers; [ raitobezarius ];
    mainProgram = "xtr";
    platforms = lib.platforms.all;
  };
}
