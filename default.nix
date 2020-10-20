{ nixpkgs ? (import <nixpkgs> {})
, system ? nixpkgs.hostPlatform
, useStatic ? true
}:
let
  systems = (import <nixpkgs/lib>).systems.examples;

  crossPkgs = (import ~/Documents/Coding/nixpkgs {
    crossSystem = system;
    #crossSystem = systems.mingwW64;
    #crossSystem = systems.musl64;
  });

  pkgs = if useStatic then crossPkgs.pkgsStatic else crossPkgs;

  stdenv = pkgs.stdenv;

  xlibressl = pkgs.libressl.overrideAttrs(old: rec {
    # Fixes build issues on Windows
    cmakeFlags = pkgs.lib.remove "-DENABLE_NC=ON" old.cmakeFlags;
    outputs    = pkgs.lib.remove "nc" old.outputs;
  });

  xcurlFull = (pkgs.curlFull.override {
    openssl        = xlibressl;
    libssh2        = pkgs.libssh2.override { openssl = xlibressl; };
    nghttp2        = pkgs.nghttp2.override { openssl = xlibressl; };

    http2Support   = true;
    idnSupport     = !stdenv.hostPlatform.isWindows;
    zlibSupport    = true;
    sslSupport     = true;
    scpSupport     = true;
    c-aresSupport  = !stdenv.hostPlatform.isWindows;

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
    ]
    ++ stdenv.lib.optionals stdenv.hostPlatform.isWindows [
      "--with-winidn"
    ];

    NIX_CFLAGS_COMPILE = stdenv.lib.optionals useStatic ["-DNGHTTP2_STATICLIB"];
  });
in
stdenv.mkDerivation rec {
  name = "nimrodg-agent";

  nativeBuildInputs = with pkgs; [
    nixpkgs.cmake # Need non-static cmake for this, rhash doesn't like pkgsStatic
    nixpkgs.git
    pkgconfig
  ];

  hardeningDisable = [ "all" ];

  buildInputs = with pkgs; [ xlibressl.dev xcurlFull.dev libuuid.dev ];

  cmakeFlags = [
    "-DNIMRODG_PLATFORM_STRING=${stdenv.hostPlatform.config}"
    "-DUSE_LTO=ON"
    "-DCMAKE_BUILD_TYPE=MinSizeRel"
    "-DOPENSSL_USE_STATIC_LIBS=${if useStatic then "ON" else "OFF"}"
  ];

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