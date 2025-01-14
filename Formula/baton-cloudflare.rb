# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonCloudflare < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.7"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-cloudflare/releases/download/v0.0.7/baton-cloudflare-v0.0.7-darwin-amd64.zip"
      sha256 "28f5adf4b9625a27c7fb5a764ca1c3deced23e8ad8d0679db90c14b718074562"

      def install
        bin.install "baton-cloudflare"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-cloudflare/releases/download/v0.0.7/baton-cloudflare-v0.0.7-darwin-arm64.zip"
      sha256 "05c1aea8e929f23f1ef71bec09f41a83635dcbb8b9a2237b9d792704e0486efa"

      def install
        bin.install "baton-cloudflare"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-cloudflare/releases/download/v0.0.7/baton-cloudflare-v0.0.7-linux-amd64.tar.gz"
        sha256 "82a490477189e30a2b86adfc8a4ac57d8e37ed1ec331d1872095891d73009fb8"

        def install
          bin.install "baton-cloudflare"
        end
      end
    end
    if Hardware::CPU.arm?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-cloudflare/releases/download/v0.0.7/baton-cloudflare-v0.0.7-linux-arm64.tar.gz"
        sha256 "0c319137affc583bd9d3bc503a0d415c21714b4b164c254a028dcfe889940ff3"

        def install
          bin.install "baton-cloudflare"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-cloudflare -v"
  end
end
