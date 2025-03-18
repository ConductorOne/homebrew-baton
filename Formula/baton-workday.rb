# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonWorkday < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.10"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-workday/releases/download/v0.0.10/baton-workday-v0.0.10-darwin-amd64.zip"
      sha256 "dc63dab7ef997f05228c04cd5a67c0166dcdbb1f594cf12b2a42197752bf8a17"

      def install
        bin.install "baton-workday"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-workday/releases/download/v0.0.10/baton-workday-v0.0.10-darwin-arm64.zip"
      sha256 "402896721e316f0e010051a4ab645073c2b1bb9c53d075d43920db64784d0da6"

      def install
        bin.install "baton-workday"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-workday/releases/download/v0.0.10/baton-workday-v0.0.10-linux-amd64.tar.gz"
        sha256 "cb1d2c38968ceb4ff5e9c99405d49fdc8f05596d1de5d8bbfbad3d836557d830"

        def install
          bin.install "baton-workday"
        end
      end
    end
    if Hardware::CPU.arm?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-workday/releases/download/v0.0.10/baton-workday-v0.0.10-linux-arm64.tar.gz"
        sha256 "0a679bfd9223cfc3aa03ee65fcef424a04283d9660fe91fea950e2f36731e80b"

        def install
          bin.install "baton-workday"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-workday -v"
  end
end
