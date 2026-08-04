{
  lib,
  stdenv,
  mdbook,
  versionSuffix ? ""
}:

let
  bookSrc = ../docs;
  commonAttrs = {
    version = "unstable${versionSuffix}";
    src = bookSrc;
    nativeBuildInputs = [ mdbook ];
    dontInstall = true;
  };
  mkDocsDerivation = attrs: stdenv.mkDerivation (commonAttrs // attrs);
in
{
  en = mkDocsDerivation {
    pname = "portail-docs-en";
    buildPhase = ''
      mdbook build book-en --dest-dir $out
    '';
  };

  fr = mkDocsDerivation {
    pname = "portail-docs-fr";
    buildPhase = ''
      mdbook build book-fr --dest-dir $out
    '';
  };

  all = mkDocsDerivation {
    pname = "portail-docs";
    buildPhase = ''
      mdbook build book-en --dest-dir $out/en
      mdbook build book-fr --dest-dir $out/fr
    '';
  };
}
