# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonAws < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.15"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-aws/releases/download/v0.0.15/baton-aws-v0.0.15-darwin-arm64.zip"
      sha256 "58a77773a2d98c6f6a5b76a55050e488b7d0dbd3b5aa89db1fdb45eac7b96c38"

      def install
        bin.install "baton-aws"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-aws/releases/download/v0.0.15/baton-aws-v0.0.15-darwin-amd64.zip"
      sha256 "e93b638f93c4e99ca7856f39cb05a80bbefc77891a2f5d18dff6b9631c5a0ddf"

      def install
        bin.install "baton-aws"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-aws/releases/download/v0.0.15/baton-aws-v0.0.15-linux-arm64.tar.gz"
      sha256 "cae61176f4c96dc379dde7ceacaee0cf761562e9b4ccbc2708ffee8f9967cbc3"

      def install
        bin.install "baton-aws"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-aws/releases/download/v0.0.15/baton-aws-v0.0.15-linux-amd64.tar.gz"
      sha256 "d304f492042d3982ce5a9e474f55b1009dbc1590263b7e5508a98ab9b07309bd"

      def install
        bin.install "baton-aws"
      end
    end
  end

  test do
    system "#{bin}/baton-aws -v"
  end
end
