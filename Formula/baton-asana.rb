# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonAsana < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.13"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-asana/releases/download/v0.0.13/baton-asana-v0.0.13-darwin-amd64.zip"
      sha256 "64496ee5c8b1031cff06d36cedc10adc3a734a13450f61b6594467630bec0d68"

      def install
        bin.install "baton-asana"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-asana/releases/download/v0.0.13/baton-asana-v0.0.13-darwin-arm64.zip"
      sha256 "61d27da28c3c7e138ba52022267e16f079b3ae5f3724320bac187c26dfd2a522"

      def install
        bin.install "baton-asana"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-asana/releases/download/v0.0.13/baton-asana-v0.0.13-linux-amd64.tar.gz"
        sha256 "6f03071e325f2320c2fc86e351ad25c22a04b4da6a17dab522749b61ca19f9ee"

        def install
          bin.install "baton-asana"
        end
      end
    end
    if Hardware::CPU.arm?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-asana/releases/download/v0.0.13/baton-asana-v0.0.13-linux-arm64.tar.gz"
        sha256 "bd03d6214fc6191c4e0fe109cffbb7f8a135fcd6bd722bce06ba3d964925d59f"

        def install
          bin.install "baton-asana"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-asana -v"
  end
end
