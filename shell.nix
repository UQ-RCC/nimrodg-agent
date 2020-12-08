{ nixpkgs ? (import <nixpkgs> {}) }:
let
  agent = (import ./default.nix {
    inherit nixpkgs;
    gitHash = "0000000000000000000000000000000000000000";
    gitDescribe = "git";
  }).overrideAttrs(old: {
    hardeningDisable = [ "all" ];
  });
in
agent
