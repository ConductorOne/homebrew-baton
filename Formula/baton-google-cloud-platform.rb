# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonGoogleCloudPlatform < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.6"

  on_macos do
    on_intel do
      url "https://github.com/ConductorOne/baton-google-cloud-platform/releases/download/v0.0.6/baton-google-cloud-platform-v0.0.6-darwin-amd64.zip"
      sha256 "cb5938408acdf4cf92b2cc5c8793af1e77d6eb867a6115a93487152ebe039881"

      def install
        bin.install "baton-google-cloud-platform"
      end
    end
    on_arm do
      url "https://github.com/ConductorOne/baton-google-cloud-platform/releases/download/v0.0.6/baton-google-cloud-platform-v0.0.6-darwin-arm64.zip"
      sha256 "332d32e30998f5ece607065aa9869919dcfdc9ce70b89048f543c5fa1f604d2e"

      def install
        bin.install "baton-google-cloud-platform"
      end
    end
  end

  on_linux do
    on_intel do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-google-cloud-platform/releases/download/v0.0.6/baton-google-cloud-platform-v0.0.6-linux-amd64.tar.gz"
        sha256 "1546dc0b72941635aeb193b8c44d1b56b5a97ee3f13b7b2de0ed90367201c0fb"

        def install
          bin.install "baton-google-cloud-platform"
        end
      end
    end
    on_arm do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-google-cloud-platform/releases/download/v0.0.6/baton-google-cloud-platform-v0.0.6-linux-arm64.tar.gz"
        sha256 "ee52ac17a5ae25245b31e0efb230e6e6fe0138e7ce703ffb6f706d634e51d7ba"

        def install
          bin.install "baton-google-cloud-platform"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-google-cloud-platform -v"
  end
end
