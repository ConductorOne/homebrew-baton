# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonAks < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.1"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-aks/releases/download/v0.0.1/baton-aks-v0.0.1-darwin-amd64.zip"
      sha256 "e9e2d423562b12f43561402c39ecec54c3e9b91ca3eabaf0e7dffdbbfcbda44b"

      def install
        bin.install "baton-aks"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-aks/releases/download/v0.0.1/baton-aks-v0.0.1-darwin-arm64.zip"
      sha256 "c13d08e6ac2150cb966bb5d929414cc87c4fc838532da7f434818e5dfd519743"

      def install
        bin.install "baton-aks"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-aks/releases/download/v0.0.1/baton-aks-v0.0.1-linux-amd64.tar.gz"
        sha256 "1e4916d10307b744a193118143fbef28b6ed5a40bc514bfd1e8744c6e3827938"

        def install
          bin.install "baton-aks"
        end
      end
    end
    if Hardware::CPU.arm?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-aks/releases/download/v0.0.1/baton-aks-v0.0.1-linux-arm64.tar.gz"
        sha256 "fa54b0168f16a88ac6cc3c12bae4b73731ce19756adac9e0668d89959c88bfea"

        def install
          bin.install "baton-aks"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-aks -v"
  end
end
