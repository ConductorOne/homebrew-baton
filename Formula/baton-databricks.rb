# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonDatabricks < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.14"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-databricks/releases/download/v0.0.14/baton-databricks-v0.0.14-darwin-amd64.zip"
      sha256 "2b89e6e76e556585535072e92cfbcc53990288a149913a731ae514405341d712"

      def install
        bin.install "baton-databricks"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-databricks/releases/download/v0.0.14/baton-databricks-v0.0.14-darwin-arm64.zip"
      sha256 "75d8f9f6ed6fdc82b84e6f80405020df36d4e745d4ce3411512ef8a40f4a66f1"

      def install
        bin.install "baton-databricks"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-databricks/releases/download/v0.0.14/baton-databricks-v0.0.14-linux-amd64.tar.gz"
        sha256 "ac8d15f7a158c59b489c862694b5408c6cdd9c65b3a92e213f180bc8ef4c2b7e"

        def install
          bin.install "baton-databricks"
        end
      end
    end
    if Hardware::CPU.arm?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-databricks/releases/download/v0.0.14/baton-databricks-v0.0.14-linux-arm64.tar.gz"
        sha256 "994709c1faa5b8fd6432dd9fc0d5a91370ffd90090d19105b0a6ff086a708881"

        def install
          bin.install "baton-databricks"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-databricks -v"
  end
end
