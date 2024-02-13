# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonRetool < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.5"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-retool/releases/download/v0.0.5/baton-retool-v0.0.5-darwin-amd64.zip"
      sha256 "3feb423b7c253d20b157e5fe0378e9ea67c9e61a8e9f3209cc291635ac06583e"

      def install
        bin.install "baton-retool"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-retool/releases/download/v0.0.5/baton-retool-v0.0.5-darwin-arm64.zip"
      sha256 "a5d009bea744ef56fa0dd03da3deb884d63bd7d1dfba88a725fc3bf6b0ef7a72"

      def install
        bin.install "baton-retool"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-retool/releases/download/v0.0.5/baton-retool-v0.0.5-linux-arm64.tar.gz"
      sha256 "ce9ceb8541adc27a67f452eb2b42ea63a7bbe2f3e1b827b5999024ff3556389c"

      def install
        bin.install "baton-retool"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-retool/releases/download/v0.0.5/baton-retool-v0.0.5-linux-amd64.tar.gz"
      sha256 "ba6eb7d7717421657fd75c1c21e311bdddcbba515a050dca5c1681f4273cfa79"

      def install
        bin.install "baton-retool"
      end
    end
  end

  test do
    system "#{bin}/baton-retool -v"
  end
end
