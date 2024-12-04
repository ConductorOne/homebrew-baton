# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonSql < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.2"

  on_macos do
    on_intel do
      url "https://github.com/ConductorOne/baton-sql/releases/download/v0.0.2/baton-sql-v0.0.2-darwin-amd64.zip"
      sha256 "ae29ccc1119c3673e8a256d69d3f63140a2cabf4f4e90a5cfc5156fa6e14fe94"

      def install
        bin.install "baton-sql"
      end
    end
    on_arm do
      url "https://github.com/ConductorOne/baton-sql/releases/download/v0.0.2/baton-sql-v0.0.2-darwin-arm64.zip"
      sha256 "91824a95650b8aaab17f1ad2f741414645f28a32109980c80d0318f70cd7fd49"

      def install
        bin.install "baton-sql"
      end
    end
  end

  on_linux do
    on_intel do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-sql/releases/download/v0.0.2/baton-sql-v0.0.2-linux-amd64.tar.gz"
        sha256 "54b568fd97ef15963fd1d706050bca1af86286c4443842bfba0fe1dd1662e6c2"

        def install
          bin.install "baton-sql"
        end
      end
    end
    on_arm do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-sql/releases/download/v0.0.2/baton-sql-v0.0.2-linux-arm64.tar.gz"
        sha256 "772c0cacfce2018561b2033e64a0f62dfe9909839eedb55d248fc5b3e9754840"

        def install
          bin.install "baton-sql"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-sql -v"
  end
end
