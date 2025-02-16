# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonDemo < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.9"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-demo/releases/download/v0.0.9/baton-demo-v0.0.9-darwin-amd64.zip"
      sha256 "4311d97ca702bbde800254303e09f180f5dc8dfc7f648820c53dc407157259fe"

      def install
        bin.install "baton-demo"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-demo/releases/download/v0.0.9/baton-demo-v0.0.9-darwin-arm64.zip"
      sha256 "950f0ac8b9cd107c053a880e27e70fdf08f03a8da6c0b45cdd27b8a00ac9fcae"

      def install
        bin.install "baton-demo"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-demo/releases/download/v0.0.9/baton-demo-v0.0.9-linux-amd64.tar.gz"
        sha256 "e087922868b88856664444279ab2b32bb4c5ee1505666008953be3b5cc92c6bc"

        def install
          bin.install "baton-demo"
        end
      end
    end
    if Hardware::CPU.arm?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-demo/releases/download/v0.0.9/baton-demo-v0.0.9-linux-arm64.tar.gz"
        sha256 "b6b6886315bb0b0d8f2b28330b43d00c5ba8404a10ca0d5a67db27623db8aa9f"

        def install
          bin.install "baton-demo"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-demo -v"
  end
end
