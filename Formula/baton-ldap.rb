# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonLdap < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.2.5"

  on_macos do
    on_intel do
      url "https://github.com/ConductorOne/baton-ldap/releases/download/v0.2.5/baton-ldap-v0.2.5-darwin-amd64.zip"
      sha256 "c49ce05ca34f8e56392eaada8f393fab16faa1eb2bfee000d7ac436cb6e9c807"

      def install
        bin.install "baton-ldap"
      end
    end
    on_arm do
      url "https://github.com/ConductorOne/baton-ldap/releases/download/v0.2.5/baton-ldap-v0.2.5-darwin-arm64.zip"
      sha256 "48acab0d9f592ff3757adcccda933ae3dd6beaeb1d1b0c6213723f041ea1dc79"

      def install
        bin.install "baton-ldap"
      end
    end
  end

  on_linux do
    on_intel do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-ldap/releases/download/v0.2.5/baton-ldap-v0.2.5-linux-amd64.tar.gz"
        sha256 "38a6156b8bbf85a1b8a28c62e8e19f19b52969d05456dac625458085a94148ae"

        def install
          bin.install "baton-ldap"
        end
      end
    end
    on_arm do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-ldap/releases/download/v0.2.5/baton-ldap-v0.2.5-linux-arm64.tar.gz"
        sha256 "258f29592525630e219518b5603a9d3aa91f48438a75a3ea575a6e85273b4ae9"

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
