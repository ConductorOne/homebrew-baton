# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonLdap < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.27"

  on_macos do
    on_intel do
      url "https://github.com/ConductorOne/baton-ldap/releases/download/v0.0.27/baton-ldap-v0.0.27-darwin-amd64.zip"
      sha256 "b5c77e5cc1e8ed56ce38ab8a3598fb38d07849f60886b7f8e7fc0809144805dc"

      def install
        bin.install "baton-ldap"
      end
    end
    on_arm do
      url "https://github.com/ConductorOne/baton-ldap/releases/download/v0.0.27/baton-ldap-v0.0.27-darwin-arm64.zip"
      sha256 "33534f9e41e367e09d4273e975f7ae81d501b4059743caa379730b5c5eaddae1"

      def install
        bin.install "baton-ldap"
      end
    end
  end

  on_linux do
    on_intel do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-ldap/releases/download/v0.0.27/baton-ldap-v0.0.27-linux-amd64.tar.gz"
        sha256 "70df49e0807fcaa923bc90204db433c9fff48867de5c2c5948ac3730a033a409"

        def install
          bin.install "baton-ldap"
        end
      end
    end
    on_arm do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-ldap/releases/download/v0.0.27/baton-ldap-v0.0.27-linux-arm64.tar.gz"
        sha256 "56e47dad539adb7327c6a40be54561673ce396d348c5ea06d578b4f9254c66b8"

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
