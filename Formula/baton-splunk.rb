# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonSplunk < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.1"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-splunk/releases/download/v0.0.1/baton-splunk-v0.0.1-darwin-amd64.zip"
      sha256 "1bebb8841dafa6cb06e0cc6c4114bc944e91ac33fc7991efd23ea72dabe285c0"

      def install
        bin.install "baton-splunk"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-splunk/releases/download/v0.0.1/baton-splunk-v0.0.1-darwin-arm64.zip"
      sha256 "1aad56a05775dcee7a7e29a08d008d3559293f65dce8fdc133453b02a11260b1"

      def install
        bin.install "baton-splunk"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-splunk/releases/download/v0.0.1/baton-splunk-v0.0.1-linux-arm64.tar.gz"
      sha256 "99c71a98d9e0c06a18e456fc7e8f69c76f7ff0e3f8cce2bc2424ad74668aebc7"

      def install
        bin.install "baton-splunk"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-splunk/releases/download/v0.0.1/baton-splunk-v0.0.1-linux-amd64.tar.gz"
      sha256 "03b688eb24af5681238198d163b1bcc71827772e725ba9a12db01f33eb3ac666"

      def install
        bin.install "baton-splunk"
      end
    end
  end

  test do
    system "#{bin}/baton-splunk -v"
  end
end