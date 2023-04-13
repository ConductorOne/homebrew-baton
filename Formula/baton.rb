# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class Baton < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.12"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton/releases/download/v0.0.12/baton-v0.0.12-darwin-amd64.zip"
      sha256 "f0c355800493bd911c0d76c15e2cb389d098ca47a1c407afdd66c1db9053324e"

      def install
        bin.install "baton"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton/releases/download/v0.0.12/baton-v0.0.12-darwin-arm64.zip"
      sha256 "72917c364ce0d596a3be10ec065b791694f9d3c3df4a64e1e684c1949023f95f"

      def install
        bin.install "baton"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton/releases/download/v0.0.12/baton-v0.0.12-linux-arm64.tar.gz"
      sha256 "7582b61147badb95528331013b1912cf5ad98dbd0973fd1280d682ff9d9ff7da"

      def install
        bin.install "baton"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton/releases/download/v0.0.12/baton-v0.0.12-linux-amd64.tar.gz"
      sha256 "1e43217833af296be98be373308cc0049376395da8ea8f0e6f6447392ec03cd2"

      def install
        bin.install "baton"
      end
    end
  end

  test do
    system "#{bin}/baton -v"
  end
end
