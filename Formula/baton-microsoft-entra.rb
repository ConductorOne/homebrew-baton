# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonMicrosoftEntra < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.34"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-microsoft-entra/releases/download/v0.0.34/baton-microsoft-entra-v0.0.34-darwin-amd64.zip"
      sha256 "e7d9db91ce25204d9e18bb9780557a92136a2cc120e49071beff77bc309b9f35"

      def install
        bin.install "baton-microsoft-entra"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-microsoft-entra/releases/download/v0.0.34/baton-microsoft-entra-v0.0.34-darwin-arm64.zip"
      sha256 "00e3bfcf1630504fb008caef123f5f4dc2c25d46744fc30c72d10bc9aa839bb3"

      def install
        bin.install "baton-microsoft-entra"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-microsoft-entra/releases/download/v0.0.34/baton-microsoft-entra-v0.0.34-linux-amd64.tar.gz"
        sha256 "0290d67adde659ea61591ac95f6ec1a4b1b19ea62b284674dec28775bb561525"

        def install
          bin.install "baton-microsoft-entra"
        end
      end
    end
    if Hardware::CPU.arm?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-microsoft-entra/releases/download/v0.0.34/baton-microsoft-entra-v0.0.34-linux-arm64.tar.gz"
        sha256 "3ea01be4b42668d255f42c0367332f86407f469e907c5581ed286a13c837ab09"

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
