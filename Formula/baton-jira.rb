# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonJira < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.9"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-jira/releases/download/v0.0.9/baton-jira-v0.0.9-darwin-amd64.zip"
      sha256 "f389be5856a55f31da72f87a22590774af68dfb2a7fb555980533e9fad7a16f1"

      def install
        bin.install "baton-jira"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-jira/releases/download/v0.0.9/baton-jira-v0.0.9-darwin-arm64.zip"
      sha256 "cd15b1e352c0dda10ef87ee5f398890d06ab1764715b9b1a16bd81860a7e048a"

      def install
        bin.install "baton-jira"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-jira/releases/download/v0.0.9/baton-jira-v0.0.9-linux-amd64.tar.gz"
      sha256 "63bea2ff8943d400fe54070d98a2437c0a6c916ddb4535078f857b9d67bff267"

      def install
        bin.install "baton-jira"
      end
    end
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-jira/releases/download/v0.0.9/baton-jira-v0.0.9-linux-arm64.tar.gz"
      sha256 "9813878b20dfebb678cb85825c6d72245bae038f60d3931cc5e1cecc1472c88c"

      def install
        bin.install "baton-jira"
      end
    end
  end

  test do
    system "#{bin}/baton-jira -v"
  end
end
