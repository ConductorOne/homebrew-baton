# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonJiraDatacenter < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.14"

  on_macos do
    on_intel do
      url "https://github.com/ConductorOne/baton-jira-datacenter/releases/download/v0.0.14/baton-jira-datacenter-v0.0.14-darwin-amd64.zip"
      sha256 "58b45597167741afc492a08b247257ec20268bcf967bfa064459fa123b7a0b9e"

      def install
        bin.install "baton-jira-datacenter"
      end
    end
    on_arm do
      url "https://github.com/ConductorOne/baton-jira-datacenter/releases/download/v0.0.14/baton-jira-datacenter-v0.0.14-darwin-arm64.zip"
      sha256 "a8f313f132648e7dd79c89ee0f706d91c029eb584791fa26fe5b8de723eb74b5"

      def install
        bin.install "baton-jira-datacenter"
      end
    end
  end

  on_linux do
    on_intel do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-jira-datacenter/releases/download/v0.0.14/baton-jira-datacenter-v0.0.14-linux-amd64.tar.gz"
        sha256 "b8bd7a8e2e969af159c4334424709344ad764cd588dec3b877ca20855e8e7abd"

        def install
          bin.install "baton-jira-datacenter"
        end
      end
    end
    on_arm do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-jira-datacenter/releases/download/v0.0.14/baton-jira-datacenter-v0.0.14-linux-arm64.tar.gz"
        sha256 "97f5500281c00d49919a8e489bcd25fc16535f3b41aaaad2753b20d64b047116"

        def install
          bin.install "baton-jira-datacenter"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-jira-datacenter -v"
  end
end
