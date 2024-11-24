{
  description = "Dactylogramme - A minimal polkit authentication agent";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }: {
    packages.x86_64-linux.default = with nixpkgs.legacyPackages.x86_64-linux; stdenv.mkDerivation {
      pname = "dactylogramme";
      version = "0.1.0";

      src = ./.;

      nativeBuildInputs = [ meson ninja pkg-config ];

      buildInputs = [ systemd ];

      installPhase = ''
        runHook preInstall
        install -Dm755 dactylogramme $out/bin/dactylogramme
        runHook postInstall
      '';
    };
  };
}
