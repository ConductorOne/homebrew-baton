# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonTeleport < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.1"

  on_macos do
    on_intel do
      url "https://github.com/ConductorOne/baton-teleport/releases/download/v0.0.1/baton-teleport-v0.0.1-darwin-amd64.zip"
      sha256 "ac61b1731b989ef2a77a59531d442e4cb948a68f98c42a386d41e8f166b4e730"

      def install
        bin.install "baton-teleport"
      end
    end
    on_arm do
      url "https://github.com/ConductorOne/baton-teleport/releases/download/v0.0.1/baton-teleport-v0.0.1-darwin-arm64.zip"
      sha256 "cf07a73507139f8e672d9239883f7fac606061b97d70197d17ba4294732cb3d7"

      def install
        bin.install "baton-teleport"
      end
    end
  end

  on_linux do
    on_intel do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-teleport/releases/download/v0.0.1/baton-teleport-v0.0.1-linux-amd64.tar.gz"
        sha256 "ec67b0390feb05ce0ee52f6a2c2417a7c54eb2aecd708f313c448b9f283fc638"

        def install
          bin.install "baton-teleport"
        end
      end
    end
    on_arm do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-teleport/releases/download/v0.0.1/baton-teleport-v0.0.1-linux-arm64.tar.gz"
        sha256 "705da07b8e76957db7cb58c8e7c2d52a20422f7bdf5cf8b0648074f1cd56286f"

        def install
          bin.install "baton-teleport"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-teleport -v"
  end
end
