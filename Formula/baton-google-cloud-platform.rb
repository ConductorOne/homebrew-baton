# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonGoogleCloudPlatform < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.15"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-google-cloud-platform/releases/download/v0.0.15/baton-google-cloud-platform-v0.0.15-darwin-amd64.zip"
      sha256 "e5dac331f4f5a94eb772cce4969c101bd6f2f00d5022da67b9cc7c814693c9f9"

      def install
        bin.install "baton-google-cloud-platform"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-google-cloud-platform/releases/download/v0.0.15/baton-google-cloud-platform-v0.0.15-darwin-arm64.zip"
      sha256 "10959ad5c95ab865a8fc2de9703b31081952afbb092c414fa90980d9c70d1387"

      def install
        bin.install "baton-google-cloud-platform"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel? and Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-google-cloud-platform/releases/download/v0.0.15/baton-google-cloud-platform-v0.0.15-linux-amd64.tar.gz"
      sha256 "687e596c0dfc33decc7bb34eb422e0b6c26b2a155bc8f4a0212f9d1ddd39aa96"
      def install
        bin.install "baton-google-cloud-platform"
      end
    end
    if Hardware::CPU.arm? and Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-google-cloud-platform/releases/download/v0.0.15/baton-google-cloud-platform-v0.0.15-linux-arm64.tar.gz"
      sha256 "6dd8f68e3711335ec79b7741eea511491c7521763b6a40648ed231685dfd837d"
      def install
        bin.install "baton-google-cloud-platform"
      end
    end
  end

  test do
    system "#{bin}/baton-google-cloud-platform -v"
  end
end
