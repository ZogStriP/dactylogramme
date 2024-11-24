{ pkgs, ... }: {
  packages = with pkgs; [ ninja meson systemdLibs ];
  languages.c.enable = true;
}
