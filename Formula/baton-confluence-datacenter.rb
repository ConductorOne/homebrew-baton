# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonConfluenceDatacenter < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.5"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-confluence-datacenter/releases/download/v0.0.5/baton-confluence-datacenter-v0.0.5-darwin-amd64.zip"
      sha256 "bac9f6226ff24202a63ea9f5875108a6169ef163e2d38224053b2e7ebc884d63"

      def install
        bin.install "baton-confluence-datacenter"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-confluence-datacenter/releases/download/v0.0.5/baton-confluence-datacenter-v0.0.5-darwin-arm64.zip"
      sha256 "0e269adbbda93c990ac9d98ae10dc138dadb84b12f55e272b84d5fd65b610432"

      def install
        bin.install "baton-confluence-datacenter"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-confluence-datacenter/releases/download/v0.0.5/baton-confluence-datacenter-v0.0.5-linux-amd64.tar.gz"
        sha256 "a44e4db1dbf6410978de548c4ff44d152a5785c06309949f7872a23ac1079471"

        def install
          bin.install "baton-confluence-datacenter"
        end
      end
    end
    if Hardware::CPU.arm?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-confluence-datacenter/releases/download/v0.0.5/baton-confluence-datacenter-v0.0.5-linux-arm64.tar.gz"
        sha256 "c512a7f4672550719a06ec0394f52048abf4d8713711429a679e2a84fa8f9d2e"

        def install
          bin.install "baton-confluence-datacenter"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-confluence-datacenter -v"
  end
end
