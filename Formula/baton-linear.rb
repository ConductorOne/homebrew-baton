# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonLinear < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.6"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-linear/releases/download/v0.0.6/baton-linear-v0.0.6-darwin-arm64.zip"
      sha256 "824e157a7326d729fed31c9ffe3bf98d0d2717ce9761101c29ed6a4be3de42bb"

      def install
        bin.install "baton-linear"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-linear/releases/download/v0.0.6/baton-linear-v0.0.6-darwin-amd64.zip"
      sha256 "3909b6fbb2b5818de6509bd18096dbdc89b1ce345327a6e8d6b3f8c2ca3f7586"

      def install
        bin.install "baton-linear"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-linear/releases/download/v0.0.6/baton-linear-v0.0.6-linux-arm64.tar.gz"
      sha256 "f3cd1b73f30477665b3dac15a7c3f73140934120d3cf7a0e3025addafd826c03"

      def install
        bin.install "baton-linear"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-linear/releases/download/v0.0.6/baton-linear-v0.0.6-linux-amd64.tar.gz"
      sha256 "71f8d2372969375e42ce8177f94e02937f95d4bfc22ba9a02be3ac909a7716a8"

      def install
        bin.install "baton-linear"
      end
    end
  end

  test do
    system "#{bin}/baton-linear -v"
  end
end
