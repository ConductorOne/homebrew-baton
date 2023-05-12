# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonDuo < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.3"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-duo/releases/download/v0.0.3/baton-duo-v0.0.3-darwin-amd64.zip"
      sha256 "7079142f733ea54e359ce3db818117a28c5268a357bbe5e572d3e536ee49845e"

      def install
        bin.install "baton-duo"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-duo/releases/download/v0.0.3/baton-duo-v0.0.3-darwin-arm64.zip"
      sha256 "a4be3a666d37aa5cb072baa808a8c9afce445d89ef5fa158000ad6747723aee6"

      def install
        bin.install "baton-duo"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-duo/releases/download/v0.0.3/baton-duo-v0.0.3-linux-arm64.tar.gz"
      sha256 "b1f2a0f9e62b50a0289aa23c77d3290efe2853a828b9e856f0071f0937f652a8"

      def install
        bin.install "baton-duo"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-duo/releases/download/v0.0.3/baton-duo-v0.0.3-linux-amd64.tar.gz"
      sha256 "f230c7bd2be6256e002930a23684c00380b7ee190013aa936b74cccdfd0cf721"

      def install
        bin.install "baton-duo"
      end
    end
  end

  test do
    system "#{bin}/baton-duo -v"
  end
end