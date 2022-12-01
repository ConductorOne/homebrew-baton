# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
require_relative "lib/custom_download_strategy"
class BatonGithub < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.8"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-github/releases/download/v0.0.8/baton-github-v0.0.8-darwin-arm64.zip", using: GitHubPrivateRepositoryReleaseDownloadStrategy
      sha256 "21ebbb2c4f43a84b1ae3033883e852548faed6836c5146e3dc9f90e35a71c134"

      def install
        bin.install "baton-github"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-github/releases/download/v0.0.8/baton-github-v0.0.8-darwin-amd64.zip", using: GitHubPrivateRepositoryReleaseDownloadStrategy
      sha256 "c1eb49d5b3339ac8522451830390f8176c169cc0a5c933077163273004b7d515"

      def install
        bin.install "baton-github"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-github/releases/download/v0.0.8/baton-github-v0.0.8-linux-arm64.tar.gz", using: GitHubPrivateRepositoryReleaseDownloadStrategy
      sha256 "6e332f481352b8c5510df23b0371b7454835a982bf76baba6d259d0b0b823769"

      def install
        bin.install "baton-github"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-github/releases/download/v0.0.8/baton-github-v0.0.8-linux-amd64.tar.gz", using: GitHubPrivateRepositoryReleaseDownloadStrategy
      sha256 "356f62d3a64565523e2a877f71b8fcd2085da4aa52767c17d7183c3ec681fa00"

      def install
        bin.install "baton-github"
      end
    end
  end

  test do
    system "#{bin}/baton-github -v"
  end
end
