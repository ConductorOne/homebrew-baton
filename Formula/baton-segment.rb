# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonSegment < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.1"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-segment/releases/download/v0.0.1/baton-segment-v0.0.1-darwin-amd64.zip"
      sha256 "63372a720940c0f210669c7882af79e5700640b2637af4a6cf777cb98072dbf3"

      def install
        bin.install "baton-segment"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-segment/releases/download/v0.0.1/baton-segment-v0.0.1-darwin-arm64.zip"
      sha256 "12e2442dacf9ba2f8e39bffadf7060f7d4bb954f8b3bd54374e5b63d05203894"

      def install
        bin.install "baton-segment"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-segment/releases/download/v0.0.1/baton-segment-v0.0.1-linux-arm64.tar.gz"
      sha256 "a268e0f0f0cd37149050e4401fa5f015918a1339d3bc67164501f136c023819f"

      def install
        bin.install "baton-segment"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-segment/releases/download/v0.0.1/baton-segment-v0.0.1-linux-amd64.tar.gz"
      sha256 "251bea6c5cce924279712cc51c245bb1831e961680858a800472d79cf4b7e611"

      def install
        bin.install "baton-segment"
      end
    end
  end

  test do
    system "#{bin}/baton-segment -v"
  end
end