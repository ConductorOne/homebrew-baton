# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonArtifactory < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.3"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-artifactory/releases/download/v0.0.3/baton-artifactory-v0.0.3-darwin-amd64.zip"
      sha256 "43a82a3eb347435558e0bb7fec9bba60b8aaef0a937cf16cead8ce88d510bc45"

      def install
        bin.install "baton-artifactory"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-artifactory/releases/download/v0.0.3/baton-artifactory-v0.0.3-darwin-arm64.zip"
      sha256 "64186f89ceca387508a607877f15547016eb387c66f34064a3ffea6049e50a7d"

      def install
        bin.install "baton-artifactory"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-artifactory/releases/download/v0.0.3/baton-artifactory-v0.0.3-linux-amd64.tar.gz"
        sha256 "28816d4966a152864ae72a61842b843e0a595c239ba2e257b27015357b3f1347"

        def install
          bin.install "baton-artifactory"
        end
      end
    end
    if Hardware::CPU.arm?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-artifactory/releases/download/v0.0.3/baton-artifactory-v0.0.3-linux-arm64.tar.gz"
        sha256 "03356fe1e170d96fce4547ffaf71bbe89c516643d96107cab5afbd9d39a99c3e"

        def install
          bin.install "baton-artifactory"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-artifactory -v"
  end
end
