# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
require_relative "lib/custom_download_strategy"
class BatonGithub < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.7"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-github/releases/download/v0.0.7/baton-github-v0.0.7-darwin-amd64.zip", using: GitHubPrivateRepositoryReleaseDownloadStrategy
      sha256 "64718996256455c835526910179865d5930ece45642c14e70d63711c484b01d8"

      def install
        bin.install "baton-github"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-github/releases/download/v0.0.7/baton-github-v0.0.7-darwin-arm64.zip", using: GitHubPrivateRepositoryReleaseDownloadStrategy
      sha256 "63b5c9c64b7f838d3b369b64a2d632e9950b856bfc31876d917fca2fb2e0ea76"

      def install
        bin.install "baton-github"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-github/releases/download/v0.0.7/baton-github-v0.0.7-linux-arm64.tar.gz", using: GitHubPrivateRepositoryReleaseDownloadStrategy
      sha256 "f6f9e8da868a29121ea8cde213a2bb20208203b2bab6d7e150dac11132656124"

      def install
        bin.install "baton-github"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-github/releases/download/v0.0.7/baton-github-v0.0.7-linux-amd64.tar.gz", using: GitHubPrivateRepositoryReleaseDownloadStrategy
      sha256 "a21f4e3dfc57df157217a0ac499bd2fbc46b13ff0feae31fee5acd64ca942417"

      def install
        bin.install "baton-github"
      end
    end
  end

  test do
    system "#{bin}/baton-github -v"
  end
end
