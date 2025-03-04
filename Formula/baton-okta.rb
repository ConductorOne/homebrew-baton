# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonOkta < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.1.40"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-okta/releases/download/v0.1.40/baton-okta-v0.1.40-darwin-amd64.zip"
      sha256 "72638026fb911724980b262ae523e8bee8ae51f7711ed41b2862ea6e87a6e268"

      def install
        bin.install "baton-okta"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-okta/releases/download/v0.1.40/baton-okta-v0.1.40-darwin-arm64.zip"
      sha256 "41f90b5cdba980ee7f1bb8c4c30b81595fb9d1072eb4d5f225d3223965ea21ee"

      def install
        bin.install "baton-okta"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-okta/releases/download/v0.1.40/baton-okta-v0.1.40-linux-amd64.tar.gz"
        sha256 "7d85a929011e08f3242aed9478c73fa008becaa772b1a908a727ef89e82ecd91"

        def install
          bin.install "baton-okta"
        end
      end
    end
    if Hardware::CPU.arm?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-okta/releases/download/v0.1.40/baton-okta-v0.1.40-linux-arm64.tar.gz"
        sha256 "a6902b1b0feb40a25c36ce3759347dd32b3c7ca70b612f759e1769329e4959da"

        def install
          bin.install "baton-okta"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-okta -v"
  end
end
