# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonNetsuite < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.6"

  on_macos do
    on_intel do
      url "https://github.com/ConductorOne/baton-netsuite/releases/download/v0.0.6/baton-netsuite-v0.0.6-darwin-amd64.zip"
      sha256 "818adbdebb8a8f8587756a04fa62d32f37a6d8bbe8cbd5475430220e311e0bd2"

      def install
        bin.install "baton-netsuite"
      end
    end
    on_arm do
      url "https://github.com/ConductorOne/baton-netsuite/releases/download/v0.0.6/baton-netsuite-v0.0.6-darwin-arm64.zip"
      sha256 "1b12075aa5771ef50917b78b7be10ea08dfeabb41cb9c3ab42c281805236735a"

      def install
        bin.install "baton-netsuite"
      end
    end
  end

  on_linux do
    on_intel do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-netsuite/releases/download/v0.0.6/baton-netsuite-v0.0.6-linux-amd64.tar.gz"
        sha256 "105d9a7170a09f2a85c4974e934f34c35d954966914adbeb42bfd937c9d38764"

        def install
          bin.install "baton-netsuite"
        end
      end
    end
    on_arm do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-netsuite/releases/download/v0.0.6/baton-netsuite-v0.0.6-linux-arm64.tar.gz"
        sha256 "0cd6edec40703a0a7d813b57dc72bf81be94a8daf525d43f6e040ea6f85ff8dc"

        def install
          bin.install "baton-netsuite"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-netsuite -v"
  end
end
