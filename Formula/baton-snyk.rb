# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonSnyk < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.2"

  on_macos do
    on_intel do
      url "https://github.com/ConductorOne/baton-snyk/releases/download/v0.0.2/baton-snyk-v0.0.2-darwin-amd64.zip"
      sha256 "9adc3e34fa7da59a05d81db2a37af1b0bf757d7e47c7d811bc0c44485f432246"

      def install
        bin.install "baton-snyk"
      end
    end
    on_arm do
      url "https://github.com/ConductorOne/baton-snyk/releases/download/v0.0.2/baton-snyk-v0.0.2-darwin-arm64.zip"
      sha256 "fddb0e155a78905eeb2bc68e444666af9f735dacfb6b5f4e9ff1d2616573b678"

      def install
        bin.install "baton-snyk"
      end
    end
  end

  on_linux do
    on_intel do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-snyk/releases/download/v0.0.2/baton-snyk-v0.0.2-linux-amd64.tar.gz"
        sha256 "fb4088975bd92db81ebc3719dddff87686cdc0c616c26f1ed01e840114e735c3"

        def install
          bin.install "baton-snyk"
        end
      end
    end
    on_arm do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-snyk/releases/download/v0.0.2/baton-snyk-v0.0.2-linux-arm64.tar.gz"
        sha256 "42cc0887a0064ea73da0dc237af5724b4f3cb6475a590bef2ecc57c928537f83"

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
