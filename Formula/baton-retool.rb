# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonRetool < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.2"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-retool/releases/download/v0.0.2/baton-retool-v0.0.2-darwin-amd64.zip"
      sha256 "a5b68f360614f7d5f124cb5cacbf6ad88bc95d0b4b33fc4d1694dd3bdda0af6c"

      def install
        bin.install "baton-retool"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-retool/releases/download/v0.0.2/baton-retool-v0.0.2-darwin-arm64.zip"
      sha256 "48b87e4da218b3ae86a4d93c6f48f06a1052ab73cb7ec3cc0feb356c01fd1f9b"

      def install
        bin.install "baton-retool"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-retool/releases/download/v0.0.2/baton-retool-v0.0.2-linux-arm64.tar.gz"
      sha256 "597df6726b6a518a1d8c1d8414c78688784d8164321be7e3c32c953395b1edb3"

      def install
        bin.install "baton-retool"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-retool/releases/download/v0.0.2/baton-retool-v0.0.2-linux-amd64.tar.gz"
      sha256 "a844716d58e223036637dcf9374d2f763940af9e62174911bc612e41ece1c5f7"

      def install
        bin.install "baton-retool"
      end
    end
  end

  test do
    system "#{bin}/baton-retool -v"
  end
end
