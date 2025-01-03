# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonBitbucketDatacenter < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.1.12"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-bitbucket-datacenter/releases/download/v0.1.12/baton-bitbucket-datacenter-v0.1.12-darwin-amd64.zip"
      sha256 "b26c8c4ecda4916f90a2383e7f19c7969a0dfc5c2acaf42a865bcb12811cc4c1"

      def install
        bin.install "baton-bitbucket-datacenter"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-bitbucket-datacenter/releases/download/v0.1.12/baton-bitbucket-datacenter-v0.1.12-darwin-arm64.zip"
      sha256 "a26993ea1492282eb58a5e447a6ab2bd06ba9f40f19f14e461073df51b277619"

      def install
        bin.install "baton-bitbucket-datacenter"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-bitbucket-datacenter/releases/download/v0.1.12/baton-bitbucket-datacenter-v0.1.12-linux-amd64.tar.gz"
        sha256 "635aa41ceccaf0cffc895e33f04c7703f7b2302c84dc8d89b56d21c2f20c0547"

        def install
          bin.install "baton-bitbucket-datacenter"
        end
      end
    end
    if Hardware::CPU.arm?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-bitbucket-datacenter/releases/download/v0.1.12/baton-bitbucket-datacenter-v0.1.12-linux-arm64.tar.gz"
        sha256 "91623ee8d8fffb331be1fa5529c5af30bae92c5a2c68207a7f1758ec4efd09ad"

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
