# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class Baton < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.2.0"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton/releases/download/v0.2.0/baton-v0.2.0-darwin-amd64.zip"
      sha256 "7c647e89ee8e918b662ff276ae5bb6e01fe3e1c5cff05fce04637900543be86a"

      def install
        bin.install "baton"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton/releases/download/v0.2.0/baton-v0.2.0-darwin-arm64.zip"
      sha256 "b2a232ccca1abb9a9a923f190ed2f4eec8b6fab1dc5607a69d491b70f9abb4d9"

      def install
        bin.install "baton"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel? and Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton/releases/download/v0.2.0/baton-v0.2.0-linux-amd64.tar.gz"
      sha256 "7f653f47e40bb958cd8854b190d16b163785e3cd52f5f701174d89c32c7c8770"
      def install
        bin.install "baton"
      end
    end
    if Hardware::CPU.arm? and Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton/releases/download/v0.2.0/baton-v0.2.0-linux-arm64.tar.gz"
      sha256 "b37baab73f23f7eaff559124a77b26e1af28c86f2c7d14aabde26dd486750ef0"
      def install
        bin.install "baton"
      end
    end
  end

  test do
    system "#{bin}/baton -v"
  end
end
