# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonCloudamqp < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.2"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-cloudamqp/releases/download/v0.0.2/baton-cloudamqp-v0.0.2-darwin-amd64.zip"
      sha256 "c5fad0091047a5b52f48c0dbf4ff00f41ec2b5010fffb58bf5672c1d839fe3e1"

      def install
        bin.install "baton-cloudamqp"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-cloudamqp/releases/download/v0.0.2/baton-cloudamqp-v0.0.2-darwin-arm64.zip"
      sha256 "4d01cc7f4dbbe14499bd0b5bf855e53adbe4978515399a8a0cacd7aca5b451fb"

      def install
        bin.install "baton-cloudamqp"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-cloudamqp/releases/download/v0.0.2/baton-cloudamqp-v0.0.2-linux-arm64.tar.gz"
      sha256 "152ea4fc560a0fa231c387479c4b0f1c568400e72ad94dce319abe93eb8df908"

      def install
        bin.install "baton-cloudamqp"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-cloudamqp/releases/download/v0.0.2/baton-cloudamqp-v0.0.2-linux-amd64.tar.gz"
      sha256 "88c49097386236051f6e9b5b38a986ceac82745423cc529ccdddee3b2be93843"

      def install
        bin.install "baton-cloudamqp"
      end
    end
  end

  test do
    system "#{bin}/baton-cloudamqp -v"
  end
end
