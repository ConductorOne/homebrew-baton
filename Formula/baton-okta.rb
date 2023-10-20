# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonOkta < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.1.1"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-okta/releases/download/v0.1.1/baton-okta-v0.1.1-darwin-amd64.zip"
      sha256 "aa0feb44acb48399e8601658ed434453c57e42659e27b7d46c8e5ba023b27e13"

      def install
        bin.install "baton-okta"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-okta/releases/download/v0.1.1/baton-okta-v0.1.1-darwin-arm64.zip"
      sha256 "4e6eeea02108bc023441d6534400ecf755bcb9dbe4ef7c6c63fa40318ed2f975"

      def install
        bin.install "baton-okta"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-okta/releases/download/v0.1.1/baton-okta-v0.1.1-linux-arm64.tar.gz"
      sha256 "c42406ae98b36f0e975a27775d7cbfba2cf464e9c68c3f7461f54ad39dc009c3"

      def install
        bin.install "baton-okta"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-okta/releases/download/v0.1.1/baton-okta-v0.1.1-linux-amd64.tar.gz"
      sha256 "8f2000b95482f551561f79bc2842476663bc135dec8f249c870ad4873bfe3478"

      def install
        bin.install "baton-okta"
      end
    end
  end

  test do
    system "#{bin}/baton-okta -v"
  end
end
