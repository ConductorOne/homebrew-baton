# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonServicenow < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.9"

  on_macos do
    on_intel do
      url "https://github.com/ConductorOne/baton-servicenow/releases/download/v0.0.9/baton-servicenow-v0.0.9-darwin-amd64.zip"
      sha256 "39cc0d92e0c7ac63faec929ed9127a6ea68846c5b22748f0038f5a57b8536d01"

      def install
        bin.install "baton-servicenow"
      end
    end
    on_arm do
      url "https://github.com/ConductorOne/baton-servicenow/releases/download/v0.0.9/baton-servicenow-v0.0.9-darwin-arm64.zip"
      sha256 "059e03bc082d3e5fe52231dbee60b397fd7e11f4ccbf0fd706a8d3904dafb3a3"

      def install
        bin.install "baton-servicenow"
      end
    end
  end

  on_linux do
    on_intel do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-servicenow/releases/download/v0.0.9/baton-servicenow-v0.0.9-linux-amd64.tar.gz"
        sha256 "1d399cd295ec741b8bb799dcf788f289f83e47ecd6a9309b96ea0686f16b9177"

        def install
          bin.install "baton-servicenow"
        end
      end
    end
    on_arm do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-servicenow/releases/download/v0.0.9/baton-servicenow-v0.0.9-linux-arm64.tar.gz"
        sha256 "8436af32fbbb523a5e5da086e7f340fbc30ed381914ac262489b70e0ac02daae"

        def install
          bin.install "baton-servicenow"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-servicenow -v"
  end
end
