# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonSnyk < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.1"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-snyk/releases/download/v0.0.1/baton-snyk-v0.0.1-darwin-arm64.zip"
      sha256 "f7ed8f5a47954d7890196d786d970cb13148d0a5696aa2cda1436c23d64944a4"

      def install
        bin.install "baton-snyk"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-snyk/releases/download/v0.0.1/baton-snyk-v0.0.1-darwin-amd64.zip"
      sha256 "8a8d93abbda0b746a18b99d7d3d00c30db309038a13ed5786e5e4c6861c14338"

      def install
        bin.install "baton-snyk"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-snyk/releases/download/v0.0.1/baton-snyk-v0.0.1-linux-arm64.tar.gz"
      sha256 "e47e8d53463b59f2f8ebd11a5e82d33532399dcda5d8904b8b5ce3f76355e789"

      def install
        bin.install "baton-snyk"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-snyk/releases/download/v0.0.1/baton-snyk-v0.0.1-linux-amd64.tar.gz"
      sha256 "8fec7f7c7a0f54c23ca87e5dc36994d1785e31eefad59857251fa8c4e89ff827"

      def install
        bin.install "baton-snyk"
      end
    end
  end

  test do
    system "#{bin}/baton-snyk -v"
  end
end
