# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonKeycloak < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.1"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-keycloak/releases/download/v0.0.1/baton-keycloak-v0.0.1-darwin-arm64.zip"
      sha256 "74289c59c70fd5d147668d993b0dba2ff995d154fe31242395fa6a4b2e41d46c"

      def install
        bin.install "baton-keycloak"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-keycloak/releases/download/v0.0.1/baton-keycloak-v0.0.1-darwin-amd64.zip"
      sha256 "99cbcf352d50ff33a0e905fb7f33984fbfa1db63e9b2c14a8f5c5d3894308c11"

      def install
        bin.install "baton-keycloak"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-keycloak/releases/download/v0.0.1/baton-keycloak-v0.0.1-linux-arm64.tar.gz"
      sha256 "0d491de8ef4bac1a73ce8b89afe0312293374b2f433949ebc547688a118498ba"

      def install
        bin.install "baton-keycloak"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-keycloak/releases/download/v0.0.1/baton-keycloak-v0.0.1-linux-amd64.tar.gz"
      sha256 "2e1843c9364eeb0374b59c56ff1e655431d8154da29f825cb2a4cb2901f61476"

      def install
        bin.install "baton-keycloak"
      end
    end
  end

  test do
    system "#{bin}/baton-keycloak -v"
  end
end
