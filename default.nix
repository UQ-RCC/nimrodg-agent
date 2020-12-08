{ nixpkgs   ? import <nixpkgs> {}
, lib       ? nixpkgs.lib
, pkgconfig ? nixpkgs.pkgconfig
, cmake     ? nixpkgs.cmake
, pkgs      ? nixpkgs
, gitHash
, gitDescribe
}:
let
  ##
  # Use the stdenv of pkgs, so we get the static compiler.
  ##
  stdenv = pkgs.stdenv;

  isStatic = stdenv.hostPlatform.isStatic;

  xlibressl = (pkgs.libressl.override {
    inherit cmake;
  }).overrideAttrs(old: rec {
    # Fixes build issues on Windows
    cmakeFlags = lib.remove "-DENABLE_NC=ON" old.cmakeFlags;
    outputs    = lib.remove "nc" old.outputs;
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
    ++ lib.optionals stdenv.hostPlatform.isWindows [
      "--with-winidn"
    ];

    NIX_CFLAGS_COMPILE = lib.optionals isStatic ["-DNGHTTP2_STATICLIB"];
  });

  xxuriparser = pkgs.uriparser.override { inherit cmake; };
  xuriparser = if isStatic then xxuriparser.overrideDerivation(old: {
    # gtest breaks when building statically
    cmakeFlags = old.cmakeFlags ++ ["-DURIPARSER_BUILD_TESTS=OFF"];
  }) else xxuriparser;
in
stdenv.mkDerivation rec {
  inherit xlibressl;
  inherit xcurlFull;
  inherit xuriparser;

  pname = "nimrodg-agent";
  version = gitDescribe;

  src = builtins.filterSource (path: type: baseNameOf path != ".git") ./.;

  nativeBuildInputs = [ nixpkgs.gitMinimal pkgconfig cmake ];

  hardeningDisable = [ "all" ];

  buildInputs = [ xlibressl.dev xcurlFull.dev xuriparser ];

  ##
  # Nimrod's always used -pc, not -unknown. I'm not game to change it.
  ##
  platformString = with stdenv.hostPlatform; if parsed.vendor.name == "unknown" then
      "${parsed.cpu.name}-${platform.name}-${parsed.kernel.name}-${parsed.abi.name}"
    else
      config;

  cmakeFlags = [
    "-DNIMRODG_PLATFORM_STRING=${platformString}"
    "-DUSE_LTO=ON"
    "-DCMAKE_BUILD_TYPE=MinSizeRel"
    "-DOPENSSL_USE_STATIC_LIBS=${if isStatic then "ON" else "OFF"}"
    "-DLIBCURL_USE_STATIC_LIBS=${if isStatic then "ON" else "OFF"}"
    "-DGIT_HASH=${gitHash}"
  ];

  enableParallelBuilding = true;

  installPhase = ''
    mkdir -p "$out/bin"
    cp bin/agent-* "$out/bin"
  '';

  meta = with stdenv.lib; {
    description = "Nimrod/G Agent";
    homepage    = "https://rcc.uq.edu.au/nimrod";
    platforms   = platforms.all;
    license     = licenses.asl20;
  };
}
