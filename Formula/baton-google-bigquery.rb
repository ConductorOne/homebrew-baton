# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonGoogleBigquery < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.8"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-google-bigquery/releases/download/v0.0.8/baton-google-bigquery-v0.0.8-darwin-amd64.zip"
      sha256 "925b8793066d9752e31764d3dc907e151bbeecaac52e0dfa0c2cae0013b1f024"

      def install
        bin.install "baton-google-bigquery"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-google-bigquery/releases/download/v0.0.8/baton-google-bigquery-v0.0.8-darwin-arm64.zip"
      sha256 "75fe7ea76b81186fb311d700506ebdef337d4bad2c810f6ce1243633ad655b99"

      def install
        bin.install "baton-google-bigquery"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-google-bigquery/releases/download/v0.0.8/baton-google-bigquery-v0.0.8-linux-amd64.tar.gz"
        sha256 "16129559acd0881f1fbc1f0567fca262cf8ed41edbcbba68daa4da46583b3555"

        def install
          bin.install "baton-google-bigquery"
        end
      end
    end
    if Hardware::CPU.arm?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-google-bigquery/releases/download/v0.0.8/baton-google-bigquery-v0.0.8-linux-arm64.tar.gz"
        sha256 "7e73d3cb41a8f980e9b52ac6538db4814a93d8c454dacf9f9e34a8624d5add78"

        def install
          bin.install "baton-google-bigquery"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-google-bigquery -v"
  end
end
