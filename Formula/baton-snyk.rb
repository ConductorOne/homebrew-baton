# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonSnyk < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.15"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-snyk/releases/download/v0.0.15/baton-snyk-v0.0.15-darwin-amd64.zip"
      sha256 "afa6f6d9ac0d881d2320bfe136bfb6ccd6a5ca4b40257387c0fbdc83fe0546c6"

      def install
        bin.install "baton-snyk"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-snyk/releases/download/v0.0.15/baton-snyk-v0.0.15-darwin-arm64.zip"
      sha256 "32a2396b32130458e8f3c9dc2cc256aed536f52462b6c643e4028478e4aa451e"

      def install
        bin.install "baton-snyk"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-snyk/releases/download/v0.0.15/baton-snyk-v0.0.15-linux-amd64.tar.gz"
        sha256 "828141329b0caf5c8d9104f14334e50566b1b70d1ca423f762c31570af99922e"

        def install
          bin.install "baton-snyk"
        end
      end
    end
    if Hardware::CPU.arm?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-snyk/releases/download/v0.0.15/baton-snyk-v0.0.15-linux-arm64.tar.gz"
        sha256 "4b249a6bdb2a09567b1beaa2b2e0aa6756f6da7c2e25d4996860c31bba43fb4f"

        def install
          bin.install "baton-snyk"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-snyk -v"
  end
end
