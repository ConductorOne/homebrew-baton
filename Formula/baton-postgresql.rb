# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonPostgresql < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.1.5"

  on_macos do
    on_intel do
      url "https://github.com/ConductorOne/baton-postgresql/releases/download/v0.1.5/baton-postgresql-v0.1.5-darwin-amd64.zip"
      sha256 "1b2a851dc5c1926f32d27b7c53c5187b1845908d0064c4fad8d3742213c170d3"

      def install
        bin.install "baton-postgresql"
      end
    end
    on_arm do
      url "https://github.com/ConductorOne/baton-postgresql/releases/download/v0.1.5/baton-postgresql-v0.1.5-darwin-arm64.zip"
      sha256 "054a0640ff74a3614d5ca9998d99eacb0a989cbddd503cc8eb14a4a6ef991e5b"

      def install
        bin.install "baton-postgresql"
      end
    end
  end

  on_linux do
    on_intel do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-postgresql/releases/download/v0.1.5/baton-postgresql-v0.1.5-linux-amd64.tar.gz"
        sha256 "0e2eaa8aa0132c94422f95334cd0f1813628fd67dbf6b4937b95e9200b3dc5cb"

        def install
          bin.install "baton-postgresql"
        end
      end
    end
    on_arm do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-postgresql/releases/download/v0.1.5/baton-postgresql-v0.1.5-linux-arm64.tar.gz"
        sha256 "8d436decdc710dab4d1b79b4c6551d69bd933bb1528de070e6e71fabee9c2b79"

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
