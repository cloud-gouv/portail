super: self: {
  portail = self.callPackage ./package.nix { };
  xtr = self.callPackage ./xtr.nix { };
}
