# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonTailscale < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.3"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-tailscale/releases/download/v0.0.3/baton-tailscale-v0.0.3-darwin-amd64.zip"
      sha256 "272203d20b2d298345a124e98d2040de91173a880abab561dac59f4fbaec3952"

      def install
        bin.install "baton-tailscale"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-tailscale/releases/download/v0.0.3/baton-tailscale-v0.0.3-darwin-arm64.zip"
      sha256 "286c35889cd9f04890e7a2889b67d4391f1e670447de494176d96a7a93241238"

      def install
        bin.install "baton-tailscale"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-tailscale/releases/download/v0.0.3/baton-tailscale-v0.0.3-linux-amd64.tar.gz"
        sha256 "fa901f51987c20a687a59c01b8d9e4ca6d1d74f647409d0bd4dc553148a91efe"

        def install
          bin.install "baton-tailscale"
        end
      end
    end
    if Hardware::CPU.arm?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-tailscale/releases/download/v0.0.3/baton-tailscale-v0.0.3-linux-arm64.tar.gz"
        sha256 "f7dcdac66cf85d15639f6d1ea69d7e714f41db4191c3a92a526ceb85a639ba5e"

        def install
          bin.install "baton-tailscale"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-tailscale -v"
  end
end
