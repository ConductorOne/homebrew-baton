# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonOkta < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.1.43"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-okta/releases/download/v0.1.43/baton-okta-v0.1.43-darwin-amd64.zip"
      sha256 "befcbb2bcae160b1c6ee3b70e78954a74dfaef0243e67fd41a579f6ec547794f"

      def install
        bin.install "baton-okta"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-okta/releases/download/v0.1.43/baton-okta-v0.1.43-darwin-arm64.zip"
      sha256 "c21c155ad04154fca9b4145cd9154e66e4ce6dda9197db4c802d185e24339a69"

      def install
        bin.install "baton-okta"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-okta/releases/download/v0.1.43/baton-okta-v0.1.43-linux-amd64.tar.gz"
        sha256 "c0a6880e080327803d135295daa93dcffc36cf510ed5f4605e84c373f62775be"

        def install
          bin.install "baton-okta"
        end
      end
    end
    if Hardware::CPU.arm?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-okta/releases/download/v0.1.43/baton-okta-v0.1.43-linux-arm64.tar.gz"
        sha256 "e2ce1f8cd0494752792b623b87053993eb7fb63716009d1e82e8969c7b815ec3"

        def install
          bin.install "baton-okta"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-okta -v"
  end
end
