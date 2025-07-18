# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonFront < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.1"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-front/releases/download/v0.0.1/baton-front-v0.0.1-darwin-amd64.zip"
      sha256 "d64c6adf436e6d12ec770d8732fbcd8ff77281e6807090542f68052eb9548892"

      def install
        bin.install "baton-front"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-front/releases/download/v0.0.1/baton-front-v0.0.1-darwin-arm64.zip"
      sha256 "20eac8e5e36a1669d701a2a258ef09e36d11cb6f91da869db1a3873d34a660b8"

      def install
        bin.install "baton-front"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-front/releases/download/v0.0.1/baton-front-v0.0.1-linux-amd64.tar.gz"
        sha256 "3a1ae21ed3f02efb69f8dd42cd2bbef19a84d4af723abf6b87eb5383c0a26c56"

        def install
          bin.install "baton-front"
        end
      end
    end
    if Hardware::CPU.arm?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-front/releases/download/v0.0.1/baton-front-v0.0.1-linux-arm64.tar.gz"
        sha256 "158105c49d1ce561f1b63ffb96d2765acb55446f3293b240872b045db9d9b19b"

        def install
          bin.install "baton-front"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-front -v"
  end
end
