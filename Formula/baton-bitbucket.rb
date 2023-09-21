# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonBitbucket < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.2"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-bitbucket/releases/download/v0.0.2/baton-bitbucket-v0.0.2-darwin-amd64.zip"
      sha256 "f8a49822487a5c552a24c2c96615029369326ce66b202f44e0c4afb48edfee9a"

      def install
        bin.install "baton-bitbucket"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-bitbucket/releases/download/v0.0.2/baton-bitbucket-v0.0.2-darwin-arm64.zip"
      sha256 "49c51de5f1d8cc2c4f5b19c48dafe3e95ae540ef8cfb9ce9675e32597c9f07a2"

      def install
        bin.install "baton-bitbucket"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-bitbucket/releases/download/v0.0.2/baton-bitbucket-v0.0.2-linux-arm64.tar.gz"
      sha256 "3d48611a394ac1e91536ec4c3fe7401221b471510a5b1b50505d7efabbc87ee4"

      def install
        bin.install "baton-bitbucket"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-bitbucket/releases/download/v0.0.2/baton-bitbucket-v0.0.2-linux-amd64.tar.gz"
      sha256 "b726edf4ac21153f39c7004f809b0720d3ddbc5167cc9785721bc8f313886486"

      def install
        bin.install "baton-bitbucket"
      end
    end
  end

  test do
    system "#{bin}/baton-bitbucket -v"
  end
end
