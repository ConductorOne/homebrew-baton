# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonRetool < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.3"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-retool/releases/download/v0.0.3/baton-retool-v0.0.3-darwin-arm64.zip"
      sha256 "65ce3f8e74ba12227b4e4a87fc762a724aeeb36531f283ccc9c40a0f239eaf86"

      def install
        bin.install "baton-retool"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-retool/releases/download/v0.0.3/baton-retool-v0.0.3-darwin-amd64.zip"
      sha256 "0aad6ff2f901c27810020096c8c91e8084ef7622c7cb5ad853e86a7a368f7699"

      def install
        bin.install "baton-retool"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-retool/releases/download/v0.0.3/baton-retool-v0.0.3-linux-arm64.tar.gz"
      sha256 "1ce7335bd2604a999be7783893724e30874be82d376a4fb960c62e7e65a5567d"

      def install
        bin.install "baton-retool"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-retool/releases/download/v0.0.3/baton-retool-v0.0.3-linux-amd64.tar.gz"
      sha256 "1126ef18df2bf7460e40e1f54595d2d38060d9f7c6b54bafb8766385f32951db"

      def install
        bin.install "baton-retool"
      end
    end
  end

  test do
    system "#{bin}/baton-retool -v"
  end
end
