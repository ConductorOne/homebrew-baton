# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonAws < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.33"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-aws/releases/download/v0.0.33/baton-aws-v0.0.33-darwin-amd64.zip"
      sha256 "1acb60ce694eaf200c5d8aa8f120112af1b8892d64ef5b59e44197e46382fcdd"

      def install
        bin.install "baton-aws"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-aws/releases/download/v0.0.33/baton-aws-v0.0.33-darwin-arm64.zip"
      sha256 "ae017dff76627282cbe25a208ba9d2344795f16b9317ad33c1f765589bc1efe5"

      def install
        bin.install "baton-aws"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-aws/releases/download/v0.0.33/baton-aws-v0.0.33-linux-amd64.tar.gz"
        sha256 "5f2661c1ce49b9dd8fdaf66eaf3d8dc48062101077c804b87635ca19b56c5215"

        def install
          bin.install "baton-aws"
        end
      end
    end
    if Hardware::CPU.arm?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-aws/releases/download/v0.0.33/baton-aws-v0.0.33-linux-arm64.tar.gz"
        sha256 "2c58a5160f2cd58dd14097d20211487e6d0bef93e28387a81f43b1225d920135"

        def install
          bin.install "baton-aws"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-aws -v"
  end
end
