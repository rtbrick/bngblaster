(import (
    fetchTarball {
      url = "https://github.com/edolstra/flake-compat/archive/5edf11c44bc78a0d334f6334cdaf7d60d732daab.tar.gz";
      sha256 = "0yqfa6rx8md81bcn4szfp0hjq2f3h9i8zjzhqqyfqdkrj5559nmw";
    }
  ) {
    src = ./.;
  })
.shellNix
