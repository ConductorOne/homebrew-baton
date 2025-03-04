# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonRetool < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.14"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-retool/releases/download/v0.0.14/baton-retool-v0.0.14-darwin-amd64.zip"
      sha256 "585afbf0f97aa2d49c4cae462379eb9b9e19c8b34c488a6d519af99679fa061c"

      def install
        bin.install "baton-retool"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-retool/releases/download/v0.0.14/baton-retool-v0.0.14-darwin-arm64.zip"
      sha256 "1696c31fdff414aef7e2a4bd6fc87c65404c4cde4d3dbce7845daf23c69f4931"

      def install
        bin.install "baton-retool"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-retool/releases/download/v0.0.14/baton-retool-v0.0.14-linux-amd64.tar.gz"
        sha256 "6d0203c3c801c306d56666afd010567b7641ae47f5ef28106c0c22347e225048"

        def install
          bin.install "baton-retool"
        end
      end
    end
    if Hardware::CPU.arm?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-retool/releases/download/v0.0.14/baton-retool-v0.0.14-linux-arm64.tar.gz"
        sha256 "8641f8b67ac71720ad27b9724ef4c7b741ef77eeca5f488f70edf76119e3483f"

        def install
          bin.install "baton-retool"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-retool -v"
  end
end
