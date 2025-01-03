# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonLdap < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.2.10"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-ldap/releases/download/v0.2.10/baton-ldap-v0.2.10-darwin-amd64.zip"
      sha256 "b258c5b2d517e754e465edfb8f783c849c1473d881f6fcb58d7270d9b3961527"

      def install
        bin.install "baton-ldap"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-ldap/releases/download/v0.2.10/baton-ldap-v0.2.10-darwin-arm64.zip"
      sha256 "20cb2ebab4374b3b2d2010f847236f676a51466c07f537ca415f105ff89db66b"

      def install
        bin.install "baton-ldap"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-ldap/releases/download/v0.2.10/baton-ldap-v0.2.10-linux-amd64.tar.gz"
        sha256 "16f38e272edfa26d1bc4d0e6971f8c4d6adab4504aab2921d2f722efff7c26ba"

        def install
          bin.install "baton-ldap"
        end
      end
    end
    if Hardware::CPU.arm?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-ldap/releases/download/v0.2.10/baton-ldap-v0.2.10-linux-arm64.tar.gz"
        sha256 "e063d6b9dd8f4dd4fa661d5fd21c422f38708e432aceca55af65f661a17a65c9"

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
