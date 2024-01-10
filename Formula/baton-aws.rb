# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonAws < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.17"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-aws/releases/download/v0.0.17/baton-aws-v0.0.17-darwin-amd64.zip"
      sha256 "5477ab87edb897d940cba1a0aa002b18ea85c059b62e3f4acee0cca03cb8a16c"

      def install
        bin.install "baton-aws"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-aws/releases/download/v0.0.17/baton-aws-v0.0.17-darwin-arm64.zip"
      sha256 "0c1ba216d10f1002a02848f0d497b03c6bf52fa5dbf3c49ae7a603ef50947b32"

      def install
        bin.install "baton-aws"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-aws/releases/download/v0.0.17/baton-aws-v0.0.17-linux-arm64.tar.gz"
      sha256 "53cef9d4ffc7eba2132b042dfd9a38833cd7d30a79d22a6984136f062bb26e7a"

      def install
        bin.install "baton-aws"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-aws/releases/download/v0.0.17/baton-aws-v0.0.17-linux-amd64.tar.gz"
      sha256 "07c8e8dc367f8a8c3ddfd2af2bf8cc247c38c9cb5be0f61c94a45871a519cada"

      def install
        bin.install "baton-aws"
      end
    end
  end

  test do
    system "#{bin}/baton-aws -v"
  end
end
