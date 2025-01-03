# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonConfluence < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.6"

  on_macos do
    on_intel do
      url "https://github.com/ConductorOne/baton-confluence/releases/download/v0.0.6/baton-confluence-v0.0.6-darwin-amd64.zip"
      sha256 "e1c09089c1cc9a8d41bb57ee2963113bf88b06bbe00e689766e0d3a5a35be611"

      def install
        bin.install "baton-confluence"
      end
    end
    on_arm do
      url "https://github.com/ConductorOne/baton-confluence/releases/download/v0.0.6/baton-confluence-v0.0.6-darwin-arm64.zip"
      sha256 "385249a0f00bcc14564982c1ba4dcecf3de079f94dc99b612befa28b6806ccc4"

      def install
        bin.install "baton-confluence"
      end
    end
  end

  on_linux do
    on_intel do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-confluence/releases/download/v0.0.6/baton-confluence-v0.0.6-linux-amd64.tar.gz"
        sha256 "60d472acfc4f8c0ea2fcbd4746c0751e9adf0f962ef7f8d69a5c4974d2d0c4dd"

        def install
          bin.install "baton-confluence"
        end
      end
    end
    on_arm do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-confluence/releases/download/v0.0.6/baton-confluence-v0.0.6-linux-arm64.tar.gz"
        sha256 "5380316a22c05932949771a278d1da50a4125045b43c3754bded0de08d80b76a"

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
