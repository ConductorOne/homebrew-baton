# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
require_relative "lib/custom_download_strategy"
class Baton < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.1"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton/releases/download/v0.0.1/baton-v0.0.1-darwin-amd64.zip", using: GitHubPrivateRepositoryReleaseDownloadStrategy
      sha256 "a0bbe5e3524488d9b872bde91bf4b06cd9898c7e37b9fbbd0f64363d9fdab1c6"

      def install
        bin.install "baton"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton/releases/download/v0.0.1/baton-v0.0.1-darwin-arm64.zip", using: GitHubPrivateRepositoryReleaseDownloadStrategy
      sha256 "ef3c6e5d88e0fcb7594d98efa376ef4a05bbfe39d2764464dfa2edbed8df45d6"

      def install
        bin.install "baton"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton/releases/download/v0.0.1/baton-v0.0.1-linux-arm64.tar.gz", using: GitHubPrivateRepositoryReleaseDownloadStrategy
      sha256 "dfedf822a305ac1dccad4791c014a87a26b17b1092e0bd3ffa4c2bef4c7f7e22"

      def install
        bin.install "baton"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton/releases/download/v0.0.1/baton-v0.0.1-linux-amd64.tar.gz", using: GitHubPrivateRepositoryReleaseDownloadStrategy
      sha256 "013c5285741bc6028fbd966ac3aa09e9d5c0915238b73026021e776d78104ad4"

      def install
        bin.install "baton"
      end
    end
  end

  test do
    system "#{bin}/baton -v"
  end
end
