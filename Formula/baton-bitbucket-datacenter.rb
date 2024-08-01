# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonBitbucketDatacenter < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.9"

  on_macos do
    on_intel do
      url "https://github.com/ConductorOne/baton-bitbucket-datacenter/releases/download/v0.0.9/baton-bitbucket-datacenter-v0.0.9-darwin-amd64.zip"
      sha256 "40c18ce5004a58cb1decadbc364ce51e5eb819df089d8a2657725acaafdda44b"

      def install
        bin.install "baton-bitbucket-datacenter"
      end
    end
    on_arm do
      url "https://github.com/ConductorOne/baton-bitbucket-datacenter/releases/download/v0.0.9/baton-bitbucket-datacenter-v0.0.9-darwin-arm64.zip"
      sha256 "4d9515168cda5c5bad9a9b5e1c624ccda7acc9f51c9f71c225e9e315d5d5cade"

      def install
        bin.install "baton-bitbucket-datacenter"
      end
    end
  end

  on_linux do
    on_intel do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-bitbucket-datacenter/releases/download/v0.0.9/baton-bitbucket-datacenter-v0.0.9-linux-amd64.tar.gz"
        sha256 "9bafb4352001c6d6a16a45db13d69649369169f48899d8245d5199f352f691b4"

        def install
          bin.install "baton-bitbucket-datacenter"
        end
      end
    end
    on_arm do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-bitbucket-datacenter/releases/download/v0.0.9/baton-bitbucket-datacenter-v0.0.9-linux-arm64.tar.gz"
        sha256 "02acb6b578f25d043a32d7e5679cdfb2611fd590a9f2ae59f790cb51496cd92f"

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
