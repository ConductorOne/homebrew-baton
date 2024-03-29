# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonXsoar < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.2"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-xsoar/releases/download/v0.0.2/baton-xsoar-v0.0.2-darwin-amd64.zip"
      sha256 "c539612d1d627f3780efd76864c0b178431065f70401c84c9cd9bc419578c38e"

      def install
        bin.install "baton-xsoar"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-xsoar/releases/download/v0.0.2/baton-xsoar-v0.0.2-darwin-arm64.zip"
      sha256 "868b6c540438584e97725f76517cc7e57f305bd4b2787af155611b1be88b62aa"

      def install
        bin.install "baton-xsoar"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-xsoar/releases/download/v0.0.2/baton-xsoar-v0.0.2-linux-arm64.tar.gz"
      sha256 "44cc5120d6879b03c5c26ea43dc6f495a83b7848074187a08dda3a0ccfdfe3e6"

      def install
        bin.install "baton-xsoar"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-xsoar/releases/download/v0.0.2/baton-xsoar-v0.0.2-linux-amd64.tar.gz"
      sha256 "7edb6620a530456e4120771c4a938ff3bce0c64251b701ffde9f418174b7fd2c"

      def install
        bin.install "baton-xsoar"
      end
    end
  end

  test do
    system "#{bin}/baton-xsoar -v"
  end
end
