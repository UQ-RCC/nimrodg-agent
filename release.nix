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

  agents = {
    musl32Static = baseAgent.override {
      pkgs = (import <nixpkgs> { crossSystem = systems.musl32; }).pkgsStatic;
    };

    musl64Static = baseAgent.override {
      pkgs = (import <nixpkgs> { crossSystem = systems.musl64; }).pkgsStatic;
    };

    win32Static = baseAgent.override {
      pkgs = (import <nixpkgs> { crossSystem = systems.mingw32; }).pkgsStatic;
    };

    win64Static = baseAgent.override {
      pkgs = (import <nixpkgs> { crossSystem = systems.mingW64; }).pkgsStatic;
    };
  };
in
nixpkgs.stdenv.mkDerivation {
  name = "nimrodg-agent-ci";
  version = gitDescribe;

  # Only build x86_64-pc-linux-musl for now
  buildInputs = [ agents.musl64Static ];

  dontUnpack = true;

  installPhase = ''
    mkdir -p $out
    cp ${agents.musl64Static}/bin/* $out
  '';
}
