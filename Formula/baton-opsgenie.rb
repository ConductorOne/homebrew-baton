# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonOpsgenie < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.2"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-opsgenie/releases/download/v0.0.2/baton-opsgenie-v0.0.2-darwin-arm64.zip"
      sha256 "42b1120c4d3e723eeae8520253f9d65a8e70de374c9e09a6ba71da1a4fd87baf"

      def install
        bin.install "baton-opsgenie"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-opsgenie/releases/download/v0.0.2/baton-opsgenie-v0.0.2-darwin-amd64.zip"
      sha256 "251e58bef956efc2d602b2e52a26bc4a9932aa74fb71b73dc5a0208b218e1d67"

      def install
        bin.install "baton-opsgenie"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-opsgenie/releases/download/v0.0.2/baton-opsgenie-v0.0.2-linux-arm64.tar.gz"
      sha256 "129b44cfdbc29d332aebd806a946bbff5914031e3b246d40b98a17f94785f417"

      def install
        bin.install "baton-opsgenie"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-opsgenie/releases/download/v0.0.2/baton-opsgenie-v0.0.2-linux-amd64.tar.gz"
      sha256 "7cef6a69dc0f3c25b77f8871ba6ae2d62aa771c6b4947d606514a6775917e4ca"

      def install
        bin.install "baton-opsgenie"
      end
    end
  end

  test do
    system "#{bin}/baton-opsgenie -v"
  end
end