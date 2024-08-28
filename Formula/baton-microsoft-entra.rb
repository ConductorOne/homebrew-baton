# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonMicrosoftEntra < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.20"

  on_macos do
    on_intel do
      url "https://github.com/ConductorOne/baton-microsoft-entra/releases/download/v0.0.20/baton-microsoft-entra-v0.0.20-darwin-amd64.zip"
      sha256 "a3a7ec11e42d3b6bfd8651a8d1c39cfa19919bd1a3ec1df4ae58a579ae6b5d98"

      def install
        bin.install "baton-microsoft-entra"
      end
    end
    on_arm do
      url "https://github.com/ConductorOne/baton-microsoft-entra/releases/download/v0.0.20/baton-microsoft-entra-v0.0.20-darwin-arm64.zip"
      sha256 "ba4af54acd39f4180c4594b12f405de793d8c1142b339d503ccec046ad0ec683"

      def install
        bin.install "baton-microsoft-entra"
      end
    end
  end

  on_linux do
    on_intel do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-microsoft-entra/releases/download/v0.0.20/baton-microsoft-entra-v0.0.20-linux-amd64.tar.gz"
        sha256 "98de7ad57dfce2b671f3fa492df9ca6c9cdb99a0a057b03d317d3bb08c767170"

        def install
          bin.install "baton-microsoft-entra"
        end
      end
    end
    on_arm do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-microsoft-entra/releases/download/v0.0.20/baton-microsoft-entra-v0.0.20-linux-arm64.tar.gz"
        sha256 "95df428d40f9494f71f0a10e153fea9a38117246531cfec2b23c6797667f58f6"

        def install
          bin.install "baton-microsoft-entra"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-microsoft-entra -v"
  end
end
