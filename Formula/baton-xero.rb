# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonXero < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.1"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-xero/releases/download/v0.0.1/baton-xero-v0.0.1-darwin-amd64.zip"
      sha256 "a9f6656b3ce375a6c215c71cd66b2a4fee8ebdf6d37a14ec943201f61b4620d8"

      def install
        bin.install "baton-xero"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-xero/releases/download/v0.0.1/baton-xero-v0.0.1-darwin-arm64.zip"
      sha256 "4e4e74b4fcf3a44ae0b361b5abe3ecc1303bc43384b2bd4243605531a8faedc1"

      def install
        bin.install "baton-xero"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-xero/releases/download/v0.0.1/baton-xero-v0.0.1-linux-arm64.tar.gz"
      sha256 "1b2dc6b9c801cc7ae81f2135c006ba944b3bbe68a62c6f7c031036aad7f3b467"

      def install
        bin.install "baton-xero"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-xero/releases/download/v0.0.1/baton-xero-v0.0.1-linux-amd64.tar.gz"
      sha256 "788dd23bb59ff51b08deaae6662c5af60d223ed9c2886660f7ecf0db55b88c74"

      def install
        bin.install "baton-xero"
      end
    end
  end

  test do
    system "#{bin}/baton-xero -v"
  end
end
