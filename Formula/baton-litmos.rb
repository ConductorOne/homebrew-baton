# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonLitmos < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.7"

  on_macos do
    on_intel do
      url "https://github.com/ConductorOne/baton-litmos/releases/download/v0.0.7/baton-litmos-v0.0.7-darwin-amd64.zip"
      sha256 "a2e7d6aa6bf219899c6610116b80379ca35b89a9b3cdceedcca4a53931a681fb"

      def install
        bin.install "baton-litmos"
      end
    end
    on_arm do
      url "https://github.com/ConductorOne/baton-litmos/releases/download/v0.0.7/baton-litmos-v0.0.7-darwin-arm64.zip"
      sha256 "fee6e5af26b6a46f4d0e9edeb8722344ecfb1e26aa941c0766fbcd2e4ed3b048"

      def install
        bin.install "baton-litmos"
      end
    end
  end

  on_linux do
    on_intel do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-litmos/releases/download/v0.0.7/baton-litmos-v0.0.7-linux-amd64.tar.gz"
        sha256 "304330139ebf469f5eac29884ba1d60e2383d5cc6f778d6e3a06845bebdeeefc"

        def install
          bin.install "baton-litmos"
        end
      end
    end
    on_arm do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-litmos/releases/download/v0.0.7/baton-litmos-v0.0.7-linux-arm64.tar.gz"
        sha256 "6eb6671f93ebf6c8361fae4a8acffd7f182fb125c58b9225db1541d446efed82"

        def install
          bin.install "baton-litmos"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-litmos -v"
  end
end
