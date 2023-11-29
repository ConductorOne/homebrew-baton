# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonSlack < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.6"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-slack/releases/download/v0.0.6/baton-slack-v0.0.6-darwin-amd64.zip"
      sha256 "20e5139042d62d6a1e0b783cf37a745ef284997a43e70b6211d3c93b1ad5792e"

      def install
        bin.install "baton-slack"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-slack/releases/download/v0.0.6/baton-slack-v0.0.6-darwin-arm64.zip"
      sha256 "d215b3fb1171173fc0db060fc2d36d7b4c7ba742e953ab043325bc1dba8720ff"

      def install
        bin.install "baton-slack"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-slack/releases/download/v0.0.6/baton-slack-v0.0.6-linux-arm64.tar.gz"
      sha256 "ac15e860c7dbf63aba2274b5358d5a7d8b1a3f855f3cb09059f3a84452e6515f"

      def install
        bin.install "baton-slack"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-slack/releases/download/v0.0.6/baton-slack-v0.0.6-linux-amd64.tar.gz"
      sha256 "a450207051fc0a00e3fff8ed9d01940d586398a82438a5b192c3c9ea9799ba86"

      def install
        bin.install "baton-slack"
      end
    end
  end

  test do
    system "#{bin}/baton-slack -v"
  end
end
