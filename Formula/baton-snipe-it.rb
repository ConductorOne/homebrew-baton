# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonSnipeIt < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.7"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-snipe-it/releases/download/v0.0.7/baton-snipe-it-v0.0.7-darwin-amd64.zip"
      sha256 "c8d8333eb264ba28deaba88fd8e81a7b49077d71f34cdbca365171317d55adb0"

      def install
        bin.install "baton-snipe-it"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-snipe-it/releases/download/v0.0.7/baton-snipe-it-v0.0.7-darwin-arm64.zip"
      sha256 "4ff4e8ebe08b0fedc6a5bd155adcbc412c6a1aa7f26d900c2a60961d96db45a7"

      def install
        bin.install "baton-snipe-it"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-snipe-it/releases/download/v0.0.7/baton-snipe-it-v0.0.7-linux-amd64.tar.gz"
      sha256 "9fdef7d8b698272b92c5669dfed54241515d28574ad4ebe769ee20b744d15638"

      def install
        bin.install "baton-snipe-it"
      end
    end
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-snipe-it/releases/download/v0.0.7/baton-snipe-it-v0.0.7-linux-arm64.tar.gz"
      sha256 "004feab04646137a93ce215a05569ce42f1ab87865e1e18e7dcf2533249c2006"

      def install
        bin.install "baton-snipe-it"
      end
    end
  end

  test do
    system "#{bin}/baton-snipe-it -v"
  end
end
