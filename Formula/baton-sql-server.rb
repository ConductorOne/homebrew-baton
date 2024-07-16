# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonSqlServer < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.3"

  on_macos do
    on_intel do
      url "https://github.com/ConductorOne/baton-sql-server/releases/download/v0.0.3/baton-sql-server-v0.0.3-darwin-amd64.zip"
      sha256 "27064e16774e39fbb5c5d187a79e358b10d2c9b5ee6e3a024b01b47126421d2d"

      def install
        bin.install "baton-sql-server"
      end
    end
    on_arm do
      url "https://github.com/ConductorOne/baton-sql-server/releases/download/v0.0.3/baton-sql-server-v0.0.3-darwin-arm64.zip"
      sha256 "57d923f191fdc85051bd74b0c628ac849a23a542a57f7eed11044a31c9cd26b1"

      def install
        bin.install "baton-sql-server"
      end
    end
  end

  on_linux do
    on_intel do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-sql-server/releases/download/v0.0.3/baton-sql-server-v0.0.3-linux-amd64.tar.gz"
        sha256 "26508efa9d4555edd009add613d9cdd6e4c5dfe3165ff9a4ef615f49a11b53dc"

        def install
          bin.install "baton-sql-server"
        end
      end
    end
    on_arm do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-sql-server/releases/download/v0.0.3/baton-sql-server-v0.0.3-linux-arm64.tar.gz"
        sha256 "5f4ce7d1a36b1b7a8138e02143c1ab53fdbd44385638c47d3920421e65250b87"

        def install
          bin.install "baton-sql-server"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-sql-server -v"
  end
end
