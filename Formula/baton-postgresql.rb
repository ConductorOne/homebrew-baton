# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonPostgresql < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.1.6"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-postgresql/releases/download/v0.1.6/baton-postgresql-v0.1.6-darwin-amd64.zip"
      sha256 "e78141f06e73d5b924bde209ce0ddeee9ef492498a41246f470ab611e5ce6e2f"

      def install
        bin.install "baton-postgresql"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-postgresql/releases/download/v0.1.6/baton-postgresql-v0.1.6-darwin-arm64.zip"
      sha256 "f424f2559f7b2c88fd337f2ca91b7bacc2d786990f8288d2ac9a19b96d7df0dd"

      def install
        bin.install "baton-postgresql"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-postgresql/releases/download/v0.1.6/baton-postgresql-v0.1.6-linux-amd64.tar.gz"
        sha256 "cab7ab9d97fff6a346fe3de1fb2e218c32ce7d4ab84f29859fb8f2b1924ac3e5"

        def install
          bin.install "baton-postgresql"
        end
      end
    end
    if Hardware::CPU.arm?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-postgresql/releases/download/v0.1.6/baton-postgresql-v0.1.6-linux-arm64.tar.gz"
        sha256 "023b6919c5d9de7ea96d9196c7c7aa8dc200f0f8ccf6d035cd1eca59035718a8"

        def install
          bin.install "baton-postgresql"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-postgresql -v"
  end
end
