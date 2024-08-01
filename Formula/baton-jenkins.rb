# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonJenkins < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.3"

  on_macos do
    on_intel do
      url "https://github.com/ConductorOne/baton-jenkins/releases/download/v0.0.3/baton-jenkins-v0.0.3-darwin-amd64.zip"
      sha256 "ce910dc594b7f471343a7b781ac7e1254cae2b299f039ed1f4af98d64fcb57c6"

      def install
        bin.install "baton-jenkins"
      end
    end
    on_arm do
      url "https://github.com/ConductorOne/baton-jenkins/releases/download/v0.0.3/baton-jenkins-v0.0.3-darwin-arm64.zip"
      sha256 "06e43d41982539c88e5b10eee64c53817f866b44355bb2fa99d3f656c64bf377"

      def install
        bin.install "baton-jenkins"
      end
    end
  end

  on_linux do
    on_intel do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-jenkins/releases/download/v0.0.3/baton-jenkins-v0.0.3-linux-amd64.tar.gz"
        sha256 "eecf37cc660eb5ff4c19fffacc5515d3b142772386a9ee0ff513bb1ca4e676d7"

        def install
          bin.install "baton-jenkins"
        end
      end
    end
    on_arm do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-jenkins/releases/download/v0.0.3/baton-jenkins-v0.0.3-linux-arm64.tar.gz"
        sha256 "fa6306f4b7fe075399a5d3ec0066ebf52168fb856ff4a28e62e07459af83ed23"

        def install
          bin.install "baton-jenkins"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-jenkins -v"
  end
end
