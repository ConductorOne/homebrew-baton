# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonBitbucketDatacenter < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.7"

  on_macos do
    on_intel do
      url "https://github.com/ConductorOne/baton-bitbucket-datacenter/releases/download/v0.0.7/baton-bitbucket-datacenter-v0.0.7-darwin-amd64.zip"
      sha256 "4a39259e44382379d3f0be808ce1c8182c2d4ea14c7effa8a19afdf534b2fffa"

      def install
        bin.install "baton-bitbucket-datacenter"
      end
    end
    on_arm do
      url "https://github.com/ConductorOne/baton-bitbucket-datacenter/releases/download/v0.0.7/baton-bitbucket-datacenter-v0.0.7-darwin-arm64.zip"
      sha256 "94eaee3c3429521d6ca9c0371f29269292c34693992105900ad2199a1b4c3794"

      def install
        bin.install "baton-bitbucket-datacenter"
      end
    end
  end

  on_linux do
    on_intel do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-bitbucket-datacenter/releases/download/v0.0.7/baton-bitbucket-datacenter-v0.0.7-linux-amd64.tar.gz"
        sha256 "eae972d39e90f8afff6b428258aafaae01272859437bfdf3ef85dd4b5df7210a"

        def install
          bin.install "baton-bitbucket-datacenter"
        end
      end
    end
    on_arm do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-bitbucket-datacenter/releases/download/v0.0.7/baton-bitbucket-datacenter-v0.0.7-linux-arm64.tar.gz"
        sha256 "37ed0b6faf3cf32560588f00127ab5115841a2d7422c6ebcc6fbec3e222b563a"

        def install
          bin.install "baton-bitbucket-datacenter"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-bitbucket-datacenter -v"
  end
end
