# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonJiraDatacenter < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.1.0"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-jira-datacenter/releases/download/v0.1.0/baton-jira-datacenter-v0.1.0-darwin-amd64.zip"
      sha256 "b4c8d6875f535b05da1827e85de32282450377a36a9884b3053dd1cd2960825c"

      def install
        bin.install "baton-jira-datacenter"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-jira-datacenter/releases/download/v0.1.0/baton-jira-datacenter-v0.1.0-darwin-arm64.zip"
      sha256 "4069efab04a13868e1bb863960cff0982320f73f7e99666b74bea1430d2e5719"

      def install
        bin.install "baton-jira-datacenter"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-jira-datacenter/releases/download/v0.1.0/baton-jira-datacenter-v0.1.0-linux-amd64.tar.gz"
        sha256 "42be665bbc42f4932ccc844a281027d38f22e58750b48ec68c1fe1081b9e0e14"

        def install
          bin.install "baton-jira-datacenter"
        end
      end
    end
    if Hardware::CPU.arm?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-jira-datacenter/releases/download/v0.1.0/baton-jira-datacenter-v0.1.0-linux-arm64.tar.gz"
        sha256 "eecc237d2077e7d37d1624fcc960bc11041512ca36346882e9248d7899a60c66"

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
