# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonJira < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.1.11"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-jira/releases/download/v0.1.11/baton-jira-v0.1.11-darwin-amd64.zip"
      sha256 "00b2b7e556448c832258d32400a7bd8114f558eacf339f8a3ae5320b7aa5d28b"

      def install
        bin.install "baton-jira"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-jira/releases/download/v0.1.11/baton-jira-v0.1.11-darwin-arm64.zip"
      sha256 "7b5cef9802902e1fb6b51bd77c50721d38e817397aee98a1fff2bfb1dba6ebf4"

      def install
        bin.install "baton-jira"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-jira/releases/download/v0.1.11/baton-jira-v0.1.11-linux-amd64.tar.gz"
        sha256 "4e294ac1b063960d372877e31c026fe9d54a5d69aee73c770f3ecb10370fdee6"

        def install
          bin.install "baton-jira"
        end
      end
    end
    if Hardware::CPU.arm?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-jira/releases/download/v0.1.11/baton-jira-v0.1.11-linux-arm64.tar.gz"
        sha256 "4e9043c0dbcd3110691993dcff238daa933e579e925f69fd368aa2cd4d070f3d"

        def install
          bin.install "baton-jira"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-jira -v"
  end
end
