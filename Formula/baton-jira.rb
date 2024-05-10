# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonJira < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.10"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-jira/releases/download/v0.0.10/baton-jira-v0.0.10-darwin-amd64.zip"
      sha256 "2ccd339acb3a7ca605135021cfd541716935eed7c3740a03876d7af951cbbf5d"

      def install
        bin.install "baton-jira"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-jira/releases/download/v0.0.10/baton-jira-v0.0.10-darwin-arm64.zip"
      sha256 "4ba9a4890e5a5c11a6d640515da2947a6b5d4171b4afced4db4831584dcedbb7"

      def install
        bin.install "baton-jira"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-jira/releases/download/v0.0.10/baton-jira-v0.0.10-linux-amd64.tar.gz"
      sha256 "cd9346d4427724f3c1648008056a4ac8b8dcba01a7748262124c6bd95921a98d"

      def install
        bin.install "baton-jira"
      end
    end
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-jira/releases/download/v0.0.10/baton-jira-v0.0.10-linux-arm64.tar.gz"
      sha256 "01be2860d549d623ea7ac7a68bfb1e37d5ea40656cbd185b969499005960f88d"

      def install
        bin.install "baton-jira"
      end
    end
  end

  test do
    system "#{bin}/baton-jira -v"
  end
end
