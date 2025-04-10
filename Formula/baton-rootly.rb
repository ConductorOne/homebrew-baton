# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonRootly < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.1"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-rootly/releases/download/v0.0.1/baton-rootly-v0.0.1-darwin-amd64.zip"
      sha256 "0b07022243cdc7e21f460cee792daa36702189bb7058fc94a543b123f362a639"

      def install
        bin.install "baton-rootly"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-rootly/releases/download/v0.0.1/baton-rootly-v0.0.1-darwin-arm64.zip"
      sha256 "b59bbe51980f8b3ebdf992971e8882853b527da14e39da81dd909cd91d962c43"

      def install
        bin.install "baton-rootly"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-rootly/releases/download/v0.0.1/baton-rootly-v0.0.1-linux-amd64.tar.gz"
        sha256 "7014b376bb94797b40080e043a712617281c3a66e81ab5c472c56de2fdc0d07f"

        def install
          bin.install "baton-rootly"
        end
      end
    end
    if Hardware::CPU.arm?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-rootly/releases/download/v0.0.1/baton-rootly-v0.0.1-linux-arm64.tar.gz"
        sha256 "95ec3f81c42470c59224a325c6d22064fa5fc5ab3ad2e22320cf01b497b866b6"

        def install
          bin.install "baton-rootly"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-rootly -v"
  end
end
