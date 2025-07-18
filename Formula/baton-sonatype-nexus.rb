# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonSonatypeNexus < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.4"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-sonatype-nexus/releases/download/v0.0.4/baton-sonatype-nexus-v0.0.4-darwin-amd64.zip"
      sha256 "8ae628eabf83972db1cdab3082077f7bf7652f1d59bb83eeb5c84f359b9c46ce"

      def install
        bin.install "baton-sonatype-nexus"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-sonatype-nexus/releases/download/v0.0.4/baton-sonatype-nexus-v0.0.4-darwin-arm64.zip"
      sha256 "44a659eb991c1032091ca79a5be3701a87fbd486457092c8d145185988aedeeb"

      def install
        bin.install "baton-sonatype-nexus"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-sonatype-nexus/releases/download/v0.0.4/baton-sonatype-nexus-v0.0.4-linux-amd64.tar.gz"
        sha256 "230cde61e752f2aaabe0cd8dc2c51d384866eadeb14447830a32f7f00383a458"

        def install
          bin.install "baton-sonatype-nexus"
        end
      end
    end
    if Hardware::CPU.arm?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-sonatype-nexus/releases/download/v0.0.4/baton-sonatype-nexus-v0.0.4-linux-arm64.tar.gz"
        sha256 "964c19b2c590bccc40e65bf0986484d5f0770ee5a3fa3b5aacb15f295bfd6838"

        def install
          bin.install "baton-sonatype-nexus"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-sonatype-nexus -v"
  end
end
