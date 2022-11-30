# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
require_relative "lib/custom_download_strategy"
class BatonAws < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.1"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-aws/releases/download/v0.0.1/baton-aws-v0.0.1-darwin-amd64.zip", using: GitHubPrivateRepositoryReleaseDownloadStrategy
      sha256 "19ed84639dfb0a32c63369a4d315329a01f674f2f5c828d9a5193a0ee41ec381"

      def install
        bin.install "baton-aws"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-aws/releases/download/v0.0.1/baton-aws-v0.0.1-darwin-arm64.zip", using: GitHubPrivateRepositoryReleaseDownloadStrategy
      sha256 "f5e7df5e29d50d133bc1d5c1eb53bf5001ec3d1206af71407abc82c7b770dd9f"

      def install
        bin.install "baton-aws"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-aws/releases/download/v0.0.1/baton-aws-v0.0.1-linux-arm64.tar.gz", using: GitHubPrivateRepositoryReleaseDownloadStrategy
      sha256 "40adf2ed75c148531159b42a0f91099d29b2c7a0ae4e8d39e184e3a9fb0e625b"

      def install
        bin.install "baton-aws"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-aws/releases/download/v0.0.1/baton-aws-v0.0.1-linux-amd64.tar.gz", using: GitHubPrivateRepositoryReleaseDownloadStrategy
      sha256 "a41d2bbcba11cc1781a9ac07f5b6493fb4f5f8319eae07a6e2da70bb30db6700"

      def install
        bin.install "baton-aws"
      end
    end
  end

  test do
    system "#{bin}/baton-aws -v"
  end
end
