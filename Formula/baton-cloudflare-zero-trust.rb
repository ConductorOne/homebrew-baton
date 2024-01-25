# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonCloudflareZeroTrust < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.3"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-cloudflare-zero-trust/releases/download/v0.0.3/baton-cloudflare-zero-trust-v0.0.3-darwin-amd64.zip"
      sha256 "62521e5ed6e4f78a3540790746df1e69c55252a6ea31fb5d79e43189de26baad"

      def install
        bin.install "baton-cloudflare-zero-trust"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-cloudflare-zero-trust/releases/download/v0.0.3/baton-cloudflare-zero-trust-v0.0.3-darwin-arm64.zip"
      sha256 "6822366b6d758f319c946b29ab1b7fc8256207806264a29227a016573fda0dc7"

      def install
        bin.install "baton-cloudflare-zero-trust"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-cloudflare-zero-trust/releases/download/v0.0.3/baton-cloudflare-zero-trust-v0.0.3-linux-arm64.tar.gz"
      sha256 "5fbfb443d7ff1eb6d8f101bed056eafe12484693e7760e3a2ce9a71863788b3e"

      def install
        bin.install "baton-cloudflare-zero-trust"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-cloudflare-zero-trust/releases/download/v0.0.3/baton-cloudflare-zero-trust-v0.0.3-linux-amd64.tar.gz"
      sha256 "aed16fe8195c000bc3a0f193cc58fc998b7fa8ba33fcf1ef65311c9a083994e6"

      def install
        bin.install "baton-cloudflare-zero-trust"
      end
    end
  end

  test do
    system "#{bin}/baton-cloudflare-zero-trust -v"
  end
end
