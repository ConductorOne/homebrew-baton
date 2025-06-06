# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonJamf < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.9"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-jamf/releases/download/v0.0.9/baton-jamf-v0.0.9-darwin-amd64.zip"
      sha256 "d3e6486944c3921cb105fcb07b0a71cf96acfa1db0c89260aaa46f94086d1cb5"

      def install
        bin.install "baton-jamf"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-jamf/releases/download/v0.0.9/baton-jamf-v0.0.9-darwin-arm64.zip"
      sha256 "56995253c3600de2fa861ec7089f65f4c714399dd0d3fb364630375da543481f"

      def install
        bin.install "baton-jamf"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel? and Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-jamf/releases/download/v0.0.9/baton-jamf-v0.0.9-linux-amd64.tar.gz"
      sha256 "cadb401c8dc4a6c7a7e28f47e8a4f9e64483b9acad26d1440a0dc3368cca6827"
      def install
        bin.install "baton-jamf"
      end
    end
    if Hardware::CPU.arm? and Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-jamf/releases/download/v0.0.9/baton-jamf-v0.0.9-linux-arm64.tar.gz"
      sha256 "d91b8140c40e41d78fa603a59a5910c0a7bbc49a013ab7dedae0e1e92104eb4c"
      def install
        bin.install "baton-jamf"
      end
    end
  end

  test do
    system "#{bin}/baton-jamf -v"
  end
end
