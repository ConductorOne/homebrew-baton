# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonGithub < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.1.7"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-github/releases/download/v0.1.7/baton-github-v0.1.7-darwin-amd64.zip"
      sha256 "9ec548ffa0b805fa84c1b8372cabcefa25a2a8c465ecce1d1b8779a083beed56"

      def install
        bin.install "baton-github"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-github/releases/download/v0.1.7/baton-github-v0.1.7-darwin-arm64.zip"
      sha256 "ceffa6e439a9d9494875f7df3e85ebf820810f829a28aa17a45855d689a6cf58"

      def install
        bin.install "baton-github"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-github/releases/download/v0.1.7/baton-github-v0.1.7-linux-arm64.tar.gz"
      sha256 "970823d039aa8bf12048525637338144a07c8018e211ff600fdee7d07cf7eca8"

      def install
        bin.install "baton-github"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-github/releases/download/v0.1.7/baton-github-v0.1.7-linux-amd64.tar.gz"
      sha256 "bab78655f29af56af50beee58ad6bd793d3b887f99543a43bf17e0aae765bd40"

      def install
        bin.install "baton-github"
      end
    end
  end

  test do
    system "#{bin}/baton-github -v"
  end
end
