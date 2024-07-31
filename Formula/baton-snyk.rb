# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonSnyk < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.6"

  on_macos do
    on_intel do
      url "https://github.com/ConductorOne/baton-snyk/releases/download/v0.0.6/baton-snyk-v0.0.6-darwin-amd64.zip"
      sha256 "9290fef25ab4a0813f167754e9fa8cc62fde6f0639223951aebbc20f19e399c2"

      def install
        bin.install "baton-snyk"
      end
    end
    on_arm do
      url "https://github.com/ConductorOne/baton-snyk/releases/download/v0.0.6/baton-snyk-v0.0.6-darwin-arm64.zip"
      sha256 "a546fd96d8dfeb1f5f116b53c824031b38efd9d65f5fd09dc30d31e60e9f7f57"

      def install
        bin.install "baton-snyk"
      end
    end
  end

  on_linux do
    on_intel do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-snyk/releases/download/v0.0.6/baton-snyk-v0.0.6-linux-amd64.tar.gz"
        sha256 "7111a772bf6dc0af6a0b6078da02b3b6982014a69379aa2d8e7b745d10458f28"

        def install
          bin.install "baton-snyk"
        end
      end
    end
    on_arm do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-snyk/releases/download/v0.0.6/baton-snyk-v0.0.6-linux-arm64.tar.gz"
        sha256 "a922eff79613dc8b5dd483313d0f2a1645c143694b9e54cd4430d67378d42ba4"

        def install
          bin.install "baton-snyk"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-snyk -v"
  end
end
