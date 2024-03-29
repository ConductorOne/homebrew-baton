# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class Baton1password < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.6"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-1password/releases/download/v0.0.6/baton-1password-v0.0.6-darwin-amd64.zip"
      sha256 "b0d5712fb1edac7a83fa60efc74d9ad490d7614fc554e831c30dadddb8a21861"

      def install
        bin.install "baton-1password"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-1password/releases/download/v0.0.6/baton-1password-v0.0.6-darwin-arm64.zip"
      sha256 "ad75285bf6a9ba18b44d67b0316107c44757064cfb5dd126064d487c600dd1eb"

      def install
        bin.install "baton-1password"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-1password/releases/download/v0.0.6/baton-1password-v0.0.6-linux-arm64.tar.gz"
      sha256 "c4e8c90d5d8b85cfba63523d532f378a97c0aba96f07aaf272cfbc6790acea03"

      def install
        bin.install "baton-1password"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-1password/releases/download/v0.0.6/baton-1password-v0.0.6-linux-amd64.tar.gz"
      sha256 "07d697918b8a4dd0120d3cdd99d3634ec16f182cb6f135416c6b5a2317c419ca"

      def install
        bin.install "baton-1password"
      end
    end
  end

  test do
    system "#{bin}/baton-1password -v"
  end
end
