# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonVgs < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.1"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-vgs/releases/download/v0.0.1/baton-vgs-v0.0.1-darwin-amd64.zip"
      sha256 "ad7f9803819275c58157321ba19fb05c882e6a25d76f3e8d527a7083253001ee"

      def install
        bin.install "baton-vgs"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-vgs/releases/download/v0.0.1/baton-vgs-v0.0.1-darwin-arm64.zip"
      sha256 "706d3bc52b5576e12f1cde48b190883b8b9dd44bcdb1205efc58c6823d874025"

      def install
        bin.install "baton-vgs"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-vgs/releases/download/v0.0.1/baton-vgs-v0.0.1-linux-amd64.tar.gz"
      sha256 "d3084d95026c639dac16e27a87f40a5f3fd5f43ff5b93e66c2e8744833db2c40"

      def install
        bin.install "baton-vgs"
      end
    end
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-vgs/releases/download/v0.0.1/baton-vgs-v0.0.1-linux-arm64.tar.gz"
      sha256 "fe4d225c814fa206c191f88284fedd8ed9b5c076fc6c8d4b3f3acaf9e1eae1e9"

      def install
        bin.install "baton-vgs"
      end
    end
  end

  test do
    system "#{bin}/baton-vgs -v"
  end
end