# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonLdap < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.17"

  on_macos do
    on_intel do
      url "https://github.com/ConductorOne/baton-ldap/releases/download/v0.0.17/baton-ldap-v0.0.17-darwin-amd64.zip"
      sha256 "704893c6180fc2375fc3ed98b0e79e0748ead9c030e59e333656a64a5123c841"

      def install
        bin.install "baton-ldap"
      end
    end
    on_arm do
      url "https://github.com/ConductorOne/baton-ldap/releases/download/v0.0.17/baton-ldap-v0.0.17-darwin-arm64.zip"
      sha256 "a7221a714785d47cf2d2f338bc071bfce6a05b2c3d43f7a187ccfff17a91bc0d"

      def install
        bin.install "baton-ldap"
      end
    end
  end

  on_linux do
    on_intel do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-ldap/releases/download/v0.0.17/baton-ldap-v0.0.17-linux-amd64.tar.gz"
        sha256 "39deac4df53817cfa877c8a398a1163d09811ce5e0b8b8b8d9aedb96939d26e8"

        def install
          bin.install "baton-ldap"
        end
      end
    end
    on_arm do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-ldap/releases/download/v0.0.17/baton-ldap-v0.0.17-linux-arm64.tar.gz"
        sha256 "46eee81c506df74cb7f7dfabfa2b187f926c4c5b9d13d9e24a17cca051f98efd"

        def install
          bin.install "baton-ldap"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-ldap -v"
  end
end
