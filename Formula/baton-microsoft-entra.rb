# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonMicrosoftEntra < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.35-cn-support"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-microsoft-entra/releases/download/v0.0.35-cn-support/baton-microsoft-entra-v0.0.35-cn-support-darwin-amd64.zip"
      sha256 "b3c896439c6828206e275c6c991e35031314fda3a4f95a47112269ae8e78668d"

      def install
        bin.install "baton-microsoft-entra"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-microsoft-entra/releases/download/v0.0.35-cn-support/baton-microsoft-entra-v0.0.35-cn-support-darwin-arm64.zip"
      sha256 "a6acde00b1d8345bc186b66f5362659ba49a131e42ebb90dca838581b1b85be7"

      def install
        bin.install "baton-microsoft-entra"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-microsoft-entra/releases/download/v0.0.35-cn-support/baton-microsoft-entra-v0.0.35-cn-support-linux-amd64.tar.gz"
        sha256 "030d467784736fac9970d2b18228a0b4e24a72f8083617b773b732baf638683e"

        def install
          bin.install "baton-microsoft-entra"
        end
      end
    end
    if Hardware::CPU.arm?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-microsoft-entra/releases/download/v0.0.35-cn-support/baton-microsoft-entra-v0.0.35-cn-support-linux-arm64.tar.gz"
        sha256 "7327db03ed4701211ec1250181ff6d744945c683e3080b6a54b81d51bda9466c"

        def install
          bin.install "baton-microsoft-entra"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-microsoft-entra -v"
  end
end
