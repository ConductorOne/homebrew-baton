# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonGithub < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.11"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-github/releases/download/v0.0.11/baton-github-v0.0.11-darwin-arm64.zip"
      sha256 "fdeb2cd33f6bfdc8aaf5ae5e92daed4232b71c421ee4e672554cbfbfb122da37"

      def install
        bin.install "baton-github"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-github/releases/download/v0.0.11/baton-github-v0.0.11-darwin-amd64.zip"
      sha256 "f2cc30137df307026da610763509a42c27e096326a1d2aef7c55eb803b8ad319"

      def install
        bin.install "baton-github"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-github/releases/download/v0.0.11/baton-github-v0.0.11-linux-arm64.tar.gz"
      sha256 "ed23b5b68598d10aec34ce81be8af057d3181046018da91929b9397819e0ff85"

      def install
        bin.install "baton-github"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-github/releases/download/v0.0.11/baton-github-v0.0.11-linux-amd64.tar.gz"
      sha256 "6aee879240bdde8f0c4e2871047ee5150f841d0c1a4ccddd15b1633d8b8f0c95"

      def install
        bin.install "baton-github"
      end
    end
  end

  test do
    system "#{bin}/baton-github -v"
  end
end
