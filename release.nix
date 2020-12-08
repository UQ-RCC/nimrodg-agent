##
# Nix derivation for CI purposes.
# Invoke as:
#   nix-build release.nix \
#       --argstr gitHash $(git rev-parse HEAD) \
#       --argstr gitDescribe $(git describe)
#
# Windows builds are currently broken due to missing libuuid.
##
{ nixpkgs ? import <nixpkgs> {}, gitHash, gitDescribe }:
let
  systems   = nixpkgs.lib.systems.examples;
  baseAgent = nixpkgs.callPackage ./default.nix {
    inherit nixpkgs;
    inherit gitHash;
    inherit gitDescribe;
  };
in rec {
  musl64Static = baseAgent.override {
    pkgs = (import <nixpkgs> { crossSystem = systems.musl64; }).pkgsStatic;
  };

  release = nixpkgs.stdenv.mkDerivation {
    pname = "nimrodg-agent-release";
    version = gitDescribe;

    buildInputs = [ musl64Static ];

    dontUnpack = true;

    installPhase = ''
      mkdir -p "$out"

      cp "${musl64Static}/bin/agent-${musl64Static.platformString}" \
        "$out/agent-${musl64Static.platformString}-${gitDescribe}"

      cd "$out" && for i in *; do
        sha256sum -b "$i" > "$i.sha256"
      done
    '';
  };
}
