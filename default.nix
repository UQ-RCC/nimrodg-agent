{ nixpkgs ? (import <nixpkgs> {})
, useStatic ? true
}:

let
  #pkgs = if useStatic then nixpkgs.pkgsStatic else nixpkgs;
  pkgs = nixpkgs.pkgsStatic;
  stdenv = pkgs.stdenv;

  xlibssh2 = pkgs.libssh2.override { openssl = pkgs.libressl; };
in
stdenv.mkDerivation rec {
  name = "nimrodg-agent";

  nativeBuildInputs = with pkgs; [
    nixpkgs.cmake # Need non-static cmake for this, rhash doesn't like pkgsStatic
    nixpkgs.git
    binutils      # CMake doesn't find ar without this
    pkgconfig
  ];

  buildInputs = with pkgs; [
    libressl.dev
    xlibssh2.dev

    ((curlFull.override {
      openssl    = libressl;
      libssh2    = xlibssh2;
      nghttp2    = pkgs.nghttp2.override { openssl = pkgs.libressl; };

      http2Support   = true;
      idnSupport     = true;
      zlibSupport    = true;
      sslSupport     = true;
      scpSupport     = true;
      c-aresSupport  = true;

      ldapSupport    = false;
      gnutlsSupport  = false;
      wolfsslSupport = false;
      gssSupport     = false;
      brotliSupport  = false;
    }).overrideAttrs(old: rec {
      configureFlags = old.configureFlags ++ [
        "--disable-file"   "--disable-ldap"  "--disable-ldaps"
        "--disable-rtsp"   "--disable-proxy" "--disable-dict"
        "--disable-telnet" "--disable-pop3"  "--disable-imap"
        "--disable-smb"    "--disable-smtp"  "--disable-cookies"
        "--disable-openssl-auto-load-config"
        "--without-ca-bundle" "--without-ca-path"
      ];
    })).dev
  ];

  cmakeFlags = [ "-DNIMRODG_PLATFORM_STRING=${stdenv.hostPlatform.config}" ];
  enableParallelBuilding = true;

  src = builtins.filterSource (path: type: baseNameOf path != ".git") ./.;

  dontInstall = true;
  preFixup = ''
    mkdir -p $out/bin
    cp bin/agent-* $out/bin
  '';

  meta = with stdenv.lib; {
    description = "Nimrod/G Agent";
    homepage    = "https://rcc.uq.edu.au/nimrod";
    platforms   = platforms.all;
    license     = licenses.asl20;
  };
}