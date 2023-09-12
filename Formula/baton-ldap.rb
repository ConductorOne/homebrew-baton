# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonLdap < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.2"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-ldap/releases/download/v0.0.2/baton-ldap-v0.0.2-darwin-amd64.zip"
      sha256 "2a411d323226de959f5e777bc182d66f5e13968f9b33b056e33c256ef711cf77"

      def install
        bin.install "baton-ldap"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-ldap/releases/download/v0.0.2/baton-ldap-v0.0.2-darwin-arm64.zip"
      sha256 "e003f81873386b80231620cef507925bc8ef6cd140c6429ce5093e113520d9bb"

      def install
        bin.install "baton-ldap"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-ldap/releases/download/v0.0.2/baton-ldap-v0.0.2-linux-arm64.tar.gz"
      sha256 "ecb15277dd39da92c6191db9506d9103b9b9cdc9ecc3da1831c4a5e4f85dd4b0"

      def install
        bin.install "baton-ldap"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-ldap/releases/download/v0.0.2/baton-ldap-v0.0.2-linux-amd64.tar.gz"
      sha256 "346277e6085e3123f5f0df7674af175d70eb967d16f5c2558f1779f4dfc22f87"

      def install
        bin.install "baton-ldap"
      end
    end
  end

  test do
    system "#{bin}/baton-ldap -v"
  end
end
