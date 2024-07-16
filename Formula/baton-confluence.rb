# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonConfluence < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.2"

  on_macos do
    on_intel do
      url "https://github.com/ConductorOne/baton-confluence/releases/download/v0.0.2/baton-confluence-v0.0.2-darwin-amd64.zip"
      sha256 "6c2b353fdd52749a70bac89fcdee7323afe1e5a0ca401b7acf41076bffa899ed"

      def install
        bin.install "baton-confluence"
      end
    end
    on_arm do
      url "https://github.com/ConductorOne/baton-confluence/releases/download/v0.0.2/baton-confluence-v0.0.2-darwin-arm64.zip"
      sha256 "89b6ca586890418baf8dda6ab1e416540047d66295bf45d26778f057215af80c"

      def install
        bin.install "baton-confluence"
      end
    end
  end

  on_linux do
    on_intel do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-confluence/releases/download/v0.0.2/baton-confluence-v0.0.2-linux-amd64.tar.gz"
        sha256 "43d6b659a10e58c8e0d07f5d2a69c7b212ef1cf0e3680bc11cbd76a90650be7e"

        def install
          bin.install "baton-confluence"
        end
      end
    end
    on_arm do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-confluence/releases/download/v0.0.2/baton-confluence-v0.0.2-linux-arm64.tar.gz"
        sha256 "c0101872d6b881383b04a61b9639af26fea6e13200aaec156bf6849e16d10a5c"

        def install
          bin.install "baton-confluence"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-confluence -v"
  end
end
