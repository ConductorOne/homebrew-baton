# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonGoogleCloudPlatform < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.11"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-google-cloud-platform/releases/download/v0.0.11/baton-google-cloud-platform-v0.0.11-darwin-amd64.zip"
      sha256 "e18e4df4f9ed5141c6b223dc192388f3f60af57a5336c22425466722348664d3"

      def install
        bin.install "baton-google-cloud-platform"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-google-cloud-platform/releases/download/v0.0.11/baton-google-cloud-platform-v0.0.11-darwin-arm64.zip"
      sha256 "2101b4710b4fffac1080783b3985707a72394f9c9c0f92e89c4bfed40f949be8"

      def install
        bin.install "baton-google-cloud-platform"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-google-cloud-platform/releases/download/v0.0.11/baton-google-cloud-platform-v0.0.11-linux-amd64.tar.gz"
        sha256 "93235c30ea213b5fc0449a656e5bd44da51bc1ee6ca8678ebeef583f160fb72b"

        def install
          bin.install "baton-google-cloud-platform"
        end
      end
    end
    if Hardware::CPU.arm?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-google-cloud-platform/releases/download/v0.0.11/baton-google-cloud-platform-v0.0.11-linux-arm64.tar.gz"
        sha256 "c6cf720af3ca25d6273c511cc943c9b427076feecc051732437035b29f2291c0"

        def install
          bin.install "baton-google-cloud-platform"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-google-cloud-platform -v"
  end
end
