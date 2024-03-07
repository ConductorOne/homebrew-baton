# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonGithub < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.1.9"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-github/releases/download/v0.1.9/baton-github-v0.1.9-darwin-amd64.zip"
      sha256 "362933465cbf4d800d8823d4159e198aedbe5d1d3f9b3a6bf233aa5d90412646"

      def install
        bin.install "baton-github"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-github/releases/download/v0.1.9/baton-github-v0.1.9-darwin-arm64.zip"
      sha256 "03994e658280d26d2475766567378b80aac02b19b1840e329a1aa8f62338756a"

      def install
        bin.install "baton-github"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-github/releases/download/v0.1.9/baton-github-v0.1.9-linux-arm64.tar.gz"
      sha256 "16b5a6c895a83fbb9612b3af96fef03bf63c3cba25b878a441094dd951ef1f1f"

      def install
        bin.install "baton-github"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-github/releases/download/v0.1.9/baton-github-v0.1.9-linux-amd64.tar.gz"
      sha256 "654a94db4ac2356e4a7256d0c10d2aa49eaabe36c35142af8ccdcb549d0434e5"

      def install
        bin.install "baton-github"
      end
    end
  end

  test do
    system "#{bin}/baton-github -v"
  end
end
