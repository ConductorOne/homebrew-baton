# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
require_relative "lib/custom_download_strategy"
class Baton < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.3"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton/releases/download/v0.0.3/baton-v0.0.3-darwin-amd64.zip", using: GitHubPrivateRepositoryReleaseDownloadStrategy
      sha256 "3b0b160af9c9cb2079f2332c3646fe4dc3deea5d2aed10cee692e33bcd6542ad"

      def install
        bin.install "baton"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton/releases/download/v0.0.3/baton-v0.0.3-darwin-arm64.zip", using: GitHubPrivateRepositoryReleaseDownloadStrategy
      sha256 "f49520e750ac79bcf0a0cf281558bde1b1035612112c471fe487fb67352e6b22"

      def install
        bin.install "baton"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton/releases/download/v0.0.3/baton-v0.0.3-linux-arm64.tar.gz", using: GitHubPrivateRepositoryReleaseDownloadStrategy
      sha256 "a5481d733db11e5cd303e3c5b67b973559bc7e0df36dbf974a9ac043bdd077b8"

      def install
        bin.install "baton"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton/releases/download/v0.0.3/baton-v0.0.3-linux-amd64.tar.gz", using: GitHubPrivateRepositoryReleaseDownloadStrategy
      sha256 "ca2e524b10000377c4d78d80f5f878c2bd9b19057383525e1107a3958f505549"

      def install
        bin.install "baton"
      end
    end
  end

  test do
    system "#{bin}/baton -v"
  end
end
