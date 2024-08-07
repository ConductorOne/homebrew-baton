# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonPrivx < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.5"

  on_macos do
    on_intel do
      url "https://github.com/ConductorOne/baton-privx/releases/download/v0.0.5/baton-privx-v0.0.5-darwin-amd64.zip"
      sha256 "9befbbe732b8d7ae719110c85745082648c76c909d8792a1c94e787b032c4084"

      def install
        bin.install "baton-privx"
      end
    end
    on_arm do
      url "https://github.com/ConductorOne/baton-privx/releases/download/v0.0.5/baton-privx-v0.0.5-darwin-arm64.zip"
      sha256 "136c851a4c475ace665b675f57bdc762ce7d6ee63128c7da1a2aca4e5d5a431f"

      def install
        bin.install "baton-privx"
      end
    end
  end

  on_linux do
    on_intel do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-privx/releases/download/v0.0.5/baton-privx-v0.0.5-linux-amd64.tar.gz"
        sha256 "6481dd9e03ef5e36a0af4f5e74184f7dcea7f00049dafd0ced24da7db89986a6"

        def install
          bin.install "baton-privx"
        end
      end
    end
    on_arm do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-privx/releases/download/v0.0.5/baton-privx-v0.0.5-linux-arm64.tar.gz"
        sha256 "c581bf146d3092645a5105d37a2001cca10996e10e3729114e7f422c9bda130c"

        def install
          bin.install "baton-privx"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-privx -v"
  end
end
