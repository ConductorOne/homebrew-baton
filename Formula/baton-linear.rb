# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonLinear < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.11"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-linear/releases/download/v0.0.11/baton-linear-v0.0.11-darwin-amd64.zip"
      sha256 "06fde86a5fc21cc7fb375e9dff56d5bcf7511d0cb118f271ef006caab1af3b05"

      def install
        bin.install "baton-linear"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-linear/releases/download/v0.0.11/baton-linear-v0.0.11-darwin-arm64.zip"
      sha256 "71f68405739cf60135f736b083159274f07d551875875dd7e2d3b5e5aae89e06"

      def install
        bin.install "baton-linear"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-linear/releases/download/v0.0.11/baton-linear-v0.0.11-linux-amd64.tar.gz"
        sha256 "f74b507cb052a5ce3b914cd85b54e157c303d360e1de360a76ea7fdfd6301c17"

        def install
          bin.install "baton-linear"
        end
      end
    end
    if Hardware::CPU.arm?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-linear/releases/download/v0.0.11/baton-linear-v0.0.11-linux-arm64.tar.gz"
        sha256 "d7c36bc1d14974314e283903a731b44b1d6121d61260f0a56f1ad37c5497be0f"

        def install
          bin.install "baton-linear"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-linear -v"
  end
end
