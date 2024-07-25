# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonSnyk < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.5"

  on_macos do
    on_intel do
      url "https://github.com/ConductorOne/baton-snyk/releases/download/v0.0.5/baton-snyk-v0.0.5-darwin-amd64.zip"
      sha256 "45cb6568888f66b3b10fd87352aaff50e36cd1bb4085882398479f28ea8be808"

      def install
        bin.install "baton-snyk"
      end
    end
    on_arm do
      url "https://github.com/ConductorOne/baton-snyk/releases/download/v0.0.5/baton-snyk-v0.0.5-darwin-arm64.zip"
      sha256 "b62f17222e070e3667e3aadbf6279fc2fd1cdab5983cf9055f3cb33db958fa65"

      def install
        bin.install "baton-snyk"
      end
    end
  end

  on_linux do
    on_intel do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-snyk/releases/download/v0.0.5/baton-snyk-v0.0.5-linux-amd64.tar.gz"
        sha256 "f46c82786122a2a9fba3f3b35fa8291d5ca6b01d6561b1c7ebce7ed61a4025e3"

        def install
          bin.install "baton-snyk"
        end
      end
    end
    on_arm do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-snyk/releases/download/v0.0.5/baton-snyk-v0.0.5-linux-arm64.tar.gz"
        sha256 "84a001a9922eb35c5eb54d4392e00322130f3d98779377cf4280815796ea760d"

        def install
          bin.install "baton-snyk"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-snyk -v"
  end
end
