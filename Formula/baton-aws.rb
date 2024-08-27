# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonAws < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.27"

  on_macos do
    on_intel do
      url "https://github.com/ConductorOne/baton-aws/releases/download/v0.0.27/baton-aws-v0.0.27-darwin-amd64.zip"
      sha256 "8bf74b941cf29eb440ee466c409c89de26bfabb95765928040bc2c8977b5e80c"

      def install
        bin.install "baton-aws"
      end
    end
    on_arm do
      url "https://github.com/ConductorOne/baton-aws/releases/download/v0.0.27/baton-aws-v0.0.27-darwin-arm64.zip"
      sha256 "1bcdaa38d2666488cc05337d56bffc7f87dab8ed9a55c23f17592991556a3da7"

      def install
        bin.install "baton-aws"
      end
    end
  end

  on_linux do
    on_intel do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-aws/releases/download/v0.0.27/baton-aws-v0.0.27-linux-amd64.tar.gz"
        sha256 "d5eaa1d534866cff46c1ae556d93e128fdd8e6ebf50c76b1d3b750a15194acf3"

        def install
          bin.install "baton-aws"
        end
      end
    end
    on_arm do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-aws/releases/download/v0.0.27/baton-aws-v0.0.27-linux-arm64.tar.gz"
        sha256 "590af84129156f655672284800d4b179e8e0a60edd40f0d07dfd43bbf2c0da38"

        def install
          bin.install "baton-aws"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-aws -v"
  end
end
