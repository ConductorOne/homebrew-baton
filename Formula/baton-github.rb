# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonGithub < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.1.2"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-github/releases/download/v0.1.2/baton-github-v0.1.2-darwin-amd64.zip"
      sha256 "d4a7a02acdb8e396d66cf0c6a1a5cfcc5e8bff933492c5327ef0938f184d6b35"

      def install
        bin.install "baton-github"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-github/releases/download/v0.1.2/baton-github-v0.1.2-darwin-arm64.zip"
      sha256 "93ced4f226ddd4f11f53e2dacf5c1a862480bff8257db30723ddcf1a32373dc7"

      def install
        bin.install "baton-github"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-github/releases/download/v0.1.2/baton-github-v0.1.2-linux-arm64.tar.gz"
      sha256 "79b219e97d3e1d26df17578831da83d8c40e1a735868f109796351d652d522eb"

      def install
        bin.install "baton-github"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-github/releases/download/v0.1.2/baton-github-v0.1.2-linux-amd64.tar.gz"
      sha256 "719f152b4c51723e363f474e989e0e0fe58b0e366727ad0339a5cab1d8782e65"

      def install
        bin.install "baton-github"
      end
    end
  end

  test do
    system "#{bin}/baton-github -v"
  end
end
