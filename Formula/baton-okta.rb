# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonOkta < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.8"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-okta/releases/download/v0.0.8/baton-okta-v0.0.8-darwin-amd64.zip"
      sha256 "85b175b4633f5949f458b3dd86a55315f7237bb0009956e81e1de28f6623b5e2"

      def install
        bin.install "baton-okta"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-okta/releases/download/v0.0.8/baton-okta-v0.0.8-darwin-arm64.zip"
      sha256 "b8e8ed46b4c80b9e25750931656c51c3a5675c06979780438b289dbdd8227215"

      def install
        bin.install "baton-okta"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-okta/releases/download/v0.0.8/baton-okta-v0.0.8-linux-arm64.tar.gz"
      sha256 "8bb3610155eb0ab2f5306cc32b2733f720db7c9aa0954f13b1efa798d37bded8"

      def install
        bin.install "baton-okta"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-okta/releases/download/v0.0.8/baton-okta-v0.0.8-linux-amd64.tar.gz"
      sha256 "9e873d562789b6c78bb6f66fef1a95aec02fe0317b259988d233e17a1f6e8f6d"

      def install
        bin.install "baton-okta"
      end
    end
  end

  test do
    system "#{bin}/baton-okta -v"
  end
end
