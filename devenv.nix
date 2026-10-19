{
  pkgs,
  lib,
  config,
  inputs,
  ...
}: let
  zigbuild = target: "cargo zigbuild --release --locked --target ${target}";
in {
  languages.zig = {
    enable = true;
    lsp.enable = false;
  };

  languages.rust = {
    enable = true;
    toolchainFile = ./rust-toolchain.toml;
  };

  packages = with pkgs; [
    cargo-zigbuild
    nasm
  ];

  scripts = {
    build-aarch64-darwin.exec = zigbuild "aarch64-apple-darwin";
    build-aarch64-linux.exec = zigbuild "aarch64-unknown-linux-gnu";
    build-i686-linux.exec = zigbuild "i686-unknown-linux-gnu";
    build-x86_64-linux.exec = zigbuild "x86_64-unknown-linux-gnu";
    build-x86_64-windows.exec = zigbuild "x86_64-pc-windows-gnu";
  };

  git-hooks.hooks = {
    alejandra.enable = true;
    cargo-check.enable = true;
    clippy.enable = true;
    rustfmt.enable = true;
  };
}
