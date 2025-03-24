# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonWorkday < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.11"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-workday/releases/download/v0.0.11/baton-workday-v0.0.11-darwin-amd64.zip"
      sha256 "d1ed34e292df66abca2b746d8d2ecea7fb3d4a832bd7b32b817528d120090b21"

      def install
        bin.install "baton-workday"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-workday/releases/download/v0.0.11/baton-workday-v0.0.11-darwin-arm64.zip"
      sha256 "0a99c0c7159761d10122076d87f327d40d0c4da4d7d12c334ceb7c656ed6b338"

      def install
        bin.install "baton-workday"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-workday/releases/download/v0.0.11/baton-workday-v0.0.11-linux-amd64.tar.gz"
        sha256 "09dae41de5e1ce96d32c61fa0b168abed0e682809dd27261f4fb75c0dec2d867"

        def install
          bin.install "baton-workday"
        end
      end
    end
    if Hardware::CPU.arm?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-workday/releases/download/v0.0.11/baton-workday-v0.0.11-linux-arm64.tar.gz"
        sha256 "b89c8d4650c627ec7f18cd5b4d7b41b312c87596c5d7da74e439f5a05f7a8733"

        def install
          bin.install "baton-workday"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-workday -v"
  end
end
