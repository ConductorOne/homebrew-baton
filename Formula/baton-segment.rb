# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonSegment < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.2"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-segment/releases/download/v0.0.2/baton-segment-v0.0.2-darwin-amd64.zip"
      sha256 "9f65264a4729892b8a12d64a4d709aefcf3842edb1c8aa78277af930c79dbefe"

      def install
        bin.install "baton-segment"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-segment/releases/download/v0.0.2/baton-segment-v0.0.2-darwin-arm64.zip"
      sha256 "53da58c45101d5d14c2189c0236cd1c34d0a510eeaa2ac85ecc083dd689bc135"

      def install
        bin.install "baton-segment"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-segment/releases/download/v0.0.2/baton-segment-v0.0.2-linux-amd64.tar.gz"
      sha256 "c9e8b15caaaf27321c47a887c536ba8f45b0137bd8cf30c3d72ed5195c6e0968"

      def install
        bin.install "baton-segment"
      end
    end
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-segment/releases/download/v0.0.2/baton-segment-v0.0.2-linux-arm64.tar.gz"
      sha256 "157da1f17d4e66651e509d9b22e051bd8182deb49cb3fa507b45b3ba0e05528a"

      def install
        bin.install "baton-segment"
      end
    end
  end

  test do
    system "#{bin}/baton-segment -v"
  end
end
