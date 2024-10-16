# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonSalesforce < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.5"

  on_macos do
    on_intel do
      url "https://github.com/ConductorOne/baton-salesforce/releases/download/v0.0.5/baton-salesforce-v0.0.5-darwin-amd64.zip"
      sha256 "76a8fecb96220dc81dee5491e6bb283f60ac54f31e5c48d698e35f5ab60d90aa"

      def install
        bin.install "baton-salesforce"
      end
    end
    on_arm do
      url "https://github.com/ConductorOne/baton-salesforce/releases/download/v0.0.5/baton-salesforce-v0.0.5-darwin-arm64.zip"
      sha256 "4278ff6357e8367946409a82d89da9880acc556d89b204396e4f8bf73322bb8c"

      def install
        bin.install "baton-salesforce"
      end
    end
  end

  on_linux do
    on_intel do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-salesforce/releases/download/v0.0.5/baton-salesforce-v0.0.5-linux-amd64.tar.gz"
        sha256 "2c6daaea7e59c8721bb16ca5eed9402cc01d387c54514f8549c107d3029c3b35"

        def install
          bin.install "baton-salesforce"
        end
      end
    end
    on_arm do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-salesforce/releases/download/v0.0.5/baton-salesforce-v0.0.5-linux-arm64.tar.gz"
        sha256 "84754a8f832f1ed9b6aec786a82d8987f1907f5a24aa2dca628fa6f464928ef1"

        def install
          bin.install "baton-salesforce"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-salesforce -v"
  end
end
