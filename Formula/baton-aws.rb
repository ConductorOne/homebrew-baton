# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonAws < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.12"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-aws/releases/download/v0.0.12/baton-aws-v0.0.12-darwin-arm64.zip"
      sha256 "01d4290e9402bbe6d4643ea1b1df71f0a203befe4592b96fac4c761b7a6b258c"

      def install
        bin.install "baton-aws"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-aws/releases/download/v0.0.12/baton-aws-v0.0.12-darwin-amd64.zip"
      sha256 "5f4e3246fe992117b5d3f3ba9ad1d207f21c865f1a9a35aebf3af7be05cf2a31"

      def install
        bin.install "baton-aws"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-aws/releases/download/v0.0.12/baton-aws-v0.0.12-linux-arm64.tar.gz"
      sha256 "9ae3fa035f9499a88035b917943293bab7ab932180125491cf37ee9cb2afa7d5"

      def install
        bin.install "baton-aws"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-aws/releases/download/v0.0.12/baton-aws-v0.0.12-linux-amd64.tar.gz"
      sha256 "72185321af37d5416736f75718b94ce83606839134532e454ee8014c96464886"

      def install
        bin.install "baton-aws"
      end
    end
  end

  test do
    system "#{bin}/baton-aws -v"
  end
end
