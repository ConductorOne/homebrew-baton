# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonLdap < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.12"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-ldap/releases/download/v0.0.12/baton-ldap-v0.0.12-darwin-amd64.zip"
      sha256 "75eacbae7bfd1d24a85ac6416159dbbc77c407520e1c8df6cd69482bb4c97191"

      def install
        bin.install "baton-ldap"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-ldap/releases/download/v0.0.12/baton-ldap-v0.0.12-darwin-arm64.zip"
      sha256 "ba76d8b193147d58480fad1ad860201f92c2ec8c6a0db806c39a2e06bd291c6e"

      def install
        bin.install "baton-ldap"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-ldap/releases/download/v0.0.12/baton-ldap-v0.0.12-linux-amd64.tar.gz"
      sha256 "efba8dfe14e2bba0cb2ae1120e9abd821e093bc012121a7b0467007db926fc7a"

      def install
        bin.install "baton-ldap"
      end
    end
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-ldap/releases/download/v0.0.12/baton-ldap-v0.0.12-linux-arm64.tar.gz"
      sha256 "f44b46279219d1b237116b056aeff9b7d97718191df32acb84600fbc48aaa31f"

      def install
        bin.install "baton-ldap"
      end
    end
  end

  test do
    system "#{bin}/baton-ldap -v"
  end
end
