# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonSlack < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.28"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-slack/releases/download/v0.0.28/baton-slack-v0.0.28-darwin-amd64.zip"
      sha256 "80efea4e90605f4c1326f1f8b98b9f49e331358acdc661a001b4ca9b1ddf7082"

      def install
        bin.install "baton-slack"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-slack/releases/download/v0.0.28/baton-slack-v0.0.28-darwin-arm64.zip"
      sha256 "2c633ba74a5c9983ccb9a416a75e945c2b1dd886b0f34e18da6b57c4504609e2"

      def install
        bin.install "baton-slack"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-slack/releases/download/v0.0.28/baton-slack-v0.0.28-linux-amd64.tar.gz"
        sha256 "d538273962a10876a66ac49aadf521ef8698f500cd42f39bef538f2352c2e59b"

        def install
          bin.install "baton-slack"
        end
      end
    end
    if Hardware::CPU.arm?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-slack/releases/download/v0.0.28/baton-slack-v0.0.28-linux-arm64.tar.gz"
        sha256 "8ba02396afefa3d8326d93a4686950fabcc97e99c23180fcabb04ee27501368f"

        def install
          bin.install "baton-slack"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-slack -v"
  end
end
