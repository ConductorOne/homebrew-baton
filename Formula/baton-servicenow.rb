# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonServicenow < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.15"

  on_macos do
    on_intel do
      url "https://github.com/ConductorOne/baton-servicenow/releases/download/v0.0.15/baton-servicenow-v0.0.15-darwin-amd64.zip"
      sha256 "10359dcab79892466f6b04b428804868fffb502b8f950a405cf24a18d5159057"

      def install
        bin.install "baton-servicenow"
      end
    end
    on_arm do
      url "https://github.com/ConductorOne/baton-servicenow/releases/download/v0.0.15/baton-servicenow-v0.0.15-darwin-arm64.zip"
      sha256 "e9a735d7a47e37797629d0dc52c24350de8377d19d1b4fa71325c2ce033e12d4"

      def install
        bin.install "baton-servicenow"
      end
    end
  end

  on_linux do
    on_intel do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-servicenow/releases/download/v0.0.15/baton-servicenow-v0.0.15-linux-amd64.tar.gz"
        sha256 "2f000c2d784c838fde974e7dd394bb01cd312dd17e725ddb402b2392ad76b04c"

        def install
          bin.install "baton-servicenow"
        end
      end
    end
    on_arm do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-servicenow/releases/download/v0.0.15/baton-servicenow-v0.0.15-linux-arm64.tar.gz"
        sha256 "1183c3db9080dc2e1b3785854ef82003969db2d2696de338a427374f5c91a7f5"

        def install
          bin.install "baton-servicenow"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-servicenow -v"
  end
end
