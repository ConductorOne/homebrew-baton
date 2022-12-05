# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonGithub < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.9"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-github/releases/download/v0.0.9/baton-github-v0.0.9-darwin-amd64.zip"
      sha256 "ad3852d2cec6571dd2ac765300483183e6110953ab67256dc468699b46a26751"

      def install
        bin.install "baton-github"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-github/releases/download/v0.0.9/baton-github-v0.0.9-darwin-arm64.zip"
      sha256 "d6018a26e66223e8549cca0a9cd64c506a680c918ad212487334883a2eab74bf"

      def install
        bin.install "baton-github"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-github/releases/download/v0.0.9/baton-github-v0.0.9-linux-arm64.tar.gz"
      sha256 "4e3e5ae21d89d2fcdbd1afc25174881cd348a5ef935adf0e22ea6b1d6f751294"

      def install
        bin.install "baton-github"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-github/releases/download/v0.0.9/baton-github-v0.0.9-linux-amd64.tar.gz"
      sha256 "06f8c092f87448518e64e3d8826fe1559c43429935a759722e8add453506532f"

      def install
        bin.install "baton-github"
      end
    end
  end

  test do
    system "#{bin}/baton-github -v"
  end
end
