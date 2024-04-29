# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonGoogleWorkspace < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.10"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-google-workspace/releases/download/v0.0.10/baton-google-workspace-v0.0.10-darwin-amd64.zip"
      sha256 "bf02cfcd63b75a2d7262869f1330e6e60f58f46513bb59bc94cc4b401359832a"

      def install
        bin.install "baton-google-workspace"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-google-workspace/releases/download/v0.0.10/baton-google-workspace-v0.0.10-darwin-arm64.zip"
      sha256 "d1b6d1c67d27fb29d7631b739e5f8ed536e3b7e3f70439c552198db44616b41f"

      def install
        bin.install "baton-google-workspace"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-google-workspace/releases/download/v0.0.10/baton-google-workspace-v0.0.10-linux-amd64.tar.gz"
      sha256 "dfb6f5991db5912edc1f9b629bdb6d45cd54f6a66846933721218588d949609f"

      def install
        bin.install "baton-google-workspace"
      end
    end
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-google-workspace/releases/download/v0.0.10/baton-google-workspace-v0.0.10-linux-arm64.tar.gz"
      sha256 "1e4610d5fb1cfd2ec5efe87b37170938663985d86c20d637018f36c02dcad22e"

      def install
        bin.install "baton-google-workspace"
      end
    end
  end

  test do
    system "#{bin}/baton-google-workspace -v"
  end
end
