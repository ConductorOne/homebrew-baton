# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonNotion < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.3"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-notion/releases/download/v0.0.3/baton-notion-v0.0.3-darwin-amd64.zip"
      sha256 "1c0f763251e6f946c9dde7fe96392d86f8eee6eac4edd8d61562292bd51939dc"

      def install
        bin.install "baton-notion"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-notion/releases/download/v0.0.3/baton-notion-v0.0.3-darwin-arm64.zip"
      sha256 "35d2b0e1f5ff52553ec8b8d8cd703dbcb3acd97e265e79afa9d9196579ac6265"

      def install
        bin.install "baton-notion"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-notion/releases/download/v0.0.3/baton-notion-v0.0.3-linux-arm64.tar.gz"
      sha256 "5e6b38cdbeeeb9a000d91e603ec8c62b630424aaefe3c8ca8986af3a33d47bb3"

      def install
        bin.install "baton-notion"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-notion/releases/download/v0.0.3/baton-notion-v0.0.3-linux-amd64.tar.gz"
      sha256 "5df677c773c3953e4381439c971726655fba21a6a35bec7508c7188eb9c40bd0"

      def install
        bin.install "baton-notion"
      end
    end
  end

  test do
    system "#{bin}/baton-notion -v"
  end
end
