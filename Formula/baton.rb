# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class Baton < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.1.9"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton/releases/download/v0.1.9/baton-v0.1.9-darwin-amd64.zip"
      sha256 "ab65c6785c9559c5a2699543ae5b73ffddd1c338343b02d76db46a9bcd56c9e8"

      def install
        bin.install "baton"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton/releases/download/v0.1.9/baton-v0.1.9-darwin-arm64.zip"
      sha256 "d77e14879e94f07a5fd191bcbd79778f95d33ce636a751ad51b42e2ef1a8f24e"

      def install
        bin.install "baton"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton/releases/download/v0.1.9/baton-v0.1.9-linux-amd64.tar.gz"
        sha256 "975b3c78b5ca65b74ed86d470b95a39e6bfdca98871855b9a097a863a3ba0b97"

        def install
          bin.install "baton"
        end
      end
    end
    if Hardware::CPU.arm?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton/releases/download/v0.1.9/baton-v0.1.9-linux-arm64.tar.gz"
        sha256 "27bcb3e15a7bc5187bdd24b0a6801b6df1703eb62bc5ea24c00298d76d4e98c9"

        def install
          bin.install "baton"
        end
      end
    end
  end

  test do
    system "#{bin}/baton -v"
  end
end
