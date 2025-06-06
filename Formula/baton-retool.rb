# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonRetool < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.15"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-retool/releases/download/v0.0.15/baton-retool-v0.0.15-darwin-amd64.zip"
      sha256 "cb10fe2f645b1223f0a3971361c5257f22d4859ef9070048323d0fe21a661fcb"

      def install
        bin.install "baton-retool"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-retool/releases/download/v0.0.15/baton-retool-v0.0.15-darwin-arm64.zip"
      sha256 "f6adb16293bca59972b4f987a7e2383e111441478ebc2df8692aeb500d79dfde"

      def install
        bin.install "baton-retool"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-retool/releases/download/v0.0.15/baton-retool-v0.0.15-linux-amd64.tar.gz"
        sha256 "cab264421bc232ea8812ca821c226b740d35d814426024aa04e13027e593b3d9"

        def install
          bin.install "baton-retool"
        end
      end
    end
    if Hardware::CPU.arm?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-retool/releases/download/v0.0.15/baton-retool-v0.0.15-linux-arm64.tar.gz"
        sha256 "29e3c207fc6dbe0ccbfc72f71782a9cfe92f450e00efa12960bd50057d7b180b"

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
