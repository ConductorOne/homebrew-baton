# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonSalesforce < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.03"

  on_macos do
    on_intel do
      url "https://github.com/ConductorOne/baton-salesforce/releases/download/v0.03/baton-salesforce-v0.03-darwin-amd64.zip"
      sha256 "8ad06edd22bd0441424718ccd016ef0e35543dac52678659a4e16e0f844a2561"

      def install
        bin.install "baton-salesforce"
      end
    end
    on_arm do
      url "https://github.com/ConductorOne/baton-salesforce/releases/download/v0.03/baton-salesforce-v0.03-darwin-arm64.zip"
      sha256 "2a2481ce4620955a916e8be77608c224ae1d7c80430f525fdfe03380b11d6cc5"

      def install
        bin.install "baton-salesforce"
      end
    end
  end

  on_linux do
    on_intel do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-salesforce/releases/download/v0.03/baton-salesforce-v0.03-linux-amd64.tar.gz"
        sha256 "c39c9df212ff7591c64e4ce23344f924a27dce2cacccc2b749bd9a443e1d7950"

        def install
          bin.install "baton-salesforce"
        end
      end
    end
    on_arm do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-salesforce/releases/download/v0.03/baton-salesforce-v0.03-linux-arm64.tar.gz"
        sha256 "fdf5276cbb395489c1c636ebc7cff6c3b528a9fa9ee26f3a91995279c400019e"

        def install
          bin.install "baton-salesforce"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-salesforce -v"
  end
end
