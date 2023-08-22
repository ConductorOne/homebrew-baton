# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class Baton1password < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.3"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-1password/releases/download/v0.0.3/baton-1password-v0.0.3-darwin-amd64.zip"
      sha256 "e9dfa004f71cfb07fa78cede28e0387e0406880111e71f0b5abbad62d1c1166a"

      def install
        bin.install "baton-1password"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-1password/releases/download/v0.0.3/baton-1password-v0.0.3-darwin-arm64.zip"
      sha256 "7cab4bd1dff30ec625296ca762665aec1114bbd9f5e7559c03c6e8a4b42b15ba"

      def install
        bin.install "baton-1password"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-1password/releases/download/v0.0.3/baton-1password-v0.0.3-linux-arm64.tar.gz"
      sha256 "af642d570da964ed3b6927781619d5c2bd737a87a67a046cf021fa7473ba8bfe"

      def install
        bin.install "baton-1password"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-1password/releases/download/v0.0.3/baton-1password-v0.0.3-linux-amd64.tar.gz"
      sha256 "b01a8e6ca072eeabf0879679c9e12328ad270efb34f74b624334f2a88d76ab64"

      def install
        bin.install "baton-1password"
      end
    end
  end

  test do
    system "#{bin}/baton-1password -v"
  end
end
