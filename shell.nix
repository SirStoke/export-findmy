let
  pkgs = import <nixpkgs> { config = {}; overlays = []; };
in
pkgs.mkShellNoCC {
  packages = with pkgs; [
      rustup
      rust-analyzer
      openssl
      pkg-config
      protobuf
      binaryen
      wabt
      wasmtime
      wasmedge
      rust-analyzer
      python3
      websocat
  ];

  shellHook = ''
    export PATH="$HOME/.cargo/bin:$PATH"
    unset CC
    unset CXX
    unset AR
  '';
}
