# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonIpa < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.1.0"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-ipa/releases/download/v0.1.0/baton-ipa-v0.1.0-darwin-amd64.zip"
      sha256 "bdde5e52997192176150b35ae01e841703651fcbdf774507800fde39f6d2a1ca"

      def install
        bin.install "baton-ipa"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-ipa/releases/download/v0.1.0/baton-ipa-v0.1.0-darwin-arm64.zip"
      sha256 "4db3b2892761a54445b4f9b0b29d9ba03ad37193dacc55657c1f2cf1dd34a8ab"

      def install
        bin.install "baton-ipa"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel? and Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-ipa/releases/download/v0.1.0/baton-ipa-v0.1.0-linux-amd64.tar.gz"
      sha256 "afd832071a0c5ae7544321fd853877711c5cf6e509bee2310bb778a7864dc679"
      def install
        bin.install "baton-ipa"
      end
    end
    if Hardware::CPU.arm? and Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-ipa/releases/download/v0.1.0/baton-ipa-v0.1.0-linux-arm64.tar.gz"
      sha256 "578eee532b62116b35b0bf35126a2b79ffe7978652ccb1fe011710b929b54d4a"
      def install
        bin.install "baton-ipa"
      end
    end
  end

  test do
    system "#{bin}/baton-ipa -v"
  end
end
