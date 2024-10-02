# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonJiraDatacenter < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.16"

  on_macos do
    on_intel do
      url "https://github.com/ConductorOne/baton-jira-datacenter/releases/download/v0.0.16/baton-jira-datacenter-v0.0.16-darwin-amd64.zip"
      sha256 "cc714aac83396f07df8f61f998dc2ef79361e8343221975c79f2f0da0576ca1e"

      def install
        bin.install "baton-jira-datacenter"
      end
    end
    on_arm do
      url "https://github.com/ConductorOne/baton-jira-datacenter/releases/download/v0.0.16/baton-jira-datacenter-v0.0.16-darwin-arm64.zip"
      sha256 "f255f6ba9919fc80c77871ebe83ede5f6b3723a851e9f4b67b011819f6541fbe"

      def install
        bin.install "baton-jira-datacenter"
      end
    end
  end

  on_linux do
    on_intel do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-jira-datacenter/releases/download/v0.0.16/baton-jira-datacenter-v0.0.16-linux-amd64.tar.gz"
        sha256 "16d5fabfa20eb0aa538286c07fa0200df34eb2a2d94e0017fba77a307d29408c"

        def install
          bin.install "baton-jira-datacenter"
        end
      end
    end
    on_arm do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-jira-datacenter/releases/download/v0.0.16/baton-jira-datacenter-v0.0.16-linux-arm64.tar.gz"
        sha256 "e55dd7a145c028549ac13e9328a39de8b4b72a4ede2308fabf2c673c9d329f50"

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
