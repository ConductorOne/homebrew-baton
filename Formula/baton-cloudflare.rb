# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonCloudflare < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.6"

  on_macos do
    on_intel do
      url "https://github.com/ConductorOne/baton-cloudflare/releases/download/v0.0.6/baton-cloudflare-v0.0.6-darwin-amd64.zip"
      sha256 "9771d357d976e2ccfa8a898beca07b82774a63af6326917598734e26c014a3b6"

      def install
        bin.install "baton-cloudflare"
      end
    end
    on_arm do
      url "https://github.com/ConductorOne/baton-cloudflare/releases/download/v0.0.6/baton-cloudflare-v0.0.6-darwin-arm64.zip"
      sha256 "6547f4c64888631dab9b4ff902b7c781ad01e5fa02c4779143053c6eca3b87f6"

      def install
        bin.install "baton-cloudflare"
      end
    end
  end

  on_linux do
    on_intel do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-cloudflare/releases/download/v0.0.6/baton-cloudflare-v0.0.6-linux-amd64.tar.gz"
        sha256 "7d4ab4b35048248d6df48202e00bccdb7677036467305eaa9132746dddb7bead"

        def install
          bin.install "baton-cloudflare"
        end
      end
    end
    on_arm do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-cloudflare/releases/download/v0.0.6/baton-cloudflare-v0.0.6-linux-arm64.tar.gz"
        sha256 "f047a6c13d47da34c3ad5e7cd5a046462fa81228b215e50481c9b122608efe28"

        def install
          bin.install "baton-cloudflare"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-cloudflare -v"
  end
end
