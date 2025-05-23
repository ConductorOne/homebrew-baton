# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonGithub < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.1.31"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-github/releases/download/v0.1.31/baton-github-v0.1.31-darwin-amd64.zip"
      sha256 "cd0a38f86ffe5f8405863b2b2fa155f9d812bf8594e07723b0d60a235b768629"

      def install
        bin.install "baton-github"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-github/releases/download/v0.1.31/baton-github-v0.1.31-darwin-arm64.zip"
      sha256 "a516018558c159808e5e885937b5c2764ba7d6d01754e8ece54230183b14c9a5"

      def install
        bin.install "baton-github"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel? and Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-github/releases/download/v0.1.31/baton-github-v0.1.31-linux-amd64.tar.gz"
      sha256 "fa0d0586c258e1fb7f1f5ddc2f3c6cc0f1a0b3b6345d520352a8380328ef0e03"
      def install
        bin.install "baton-github"
      end
    end
    if Hardware::CPU.arm? and Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-github/releases/download/v0.1.31/baton-github-v0.1.31-linux-arm64.tar.gz"
      sha256 "bd6655597e2777e38edb0b15f75481037e8d96967fe25453ade8e5cfc3530bc6"
      def install
        bin.install "baton-github"
      end
    end
  end

  test do
    system "#{bin}/baton-github -v"
  end
end
