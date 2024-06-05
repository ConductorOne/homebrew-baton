# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonGoogleBigquery < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.1"

  on_macos do
    on_intel do
      url "https://github.com/ConductorOne/baton-google-bigquery/releases/download/v0.0.1/baton-google-bigquery-v0.0.1-darwin-amd64.zip"
      sha256 "57d7b6e8bd8450d58dbd346b68c438b012c63324ce4b635a1dbe12bc8c4e9e2c"

      def install
        bin.install "baton-google-bigquery"
      end
    end
    on_arm do
      url "https://github.com/ConductorOne/baton-google-bigquery/releases/download/v0.0.1/baton-google-bigquery-v0.0.1-darwin-arm64.zip"
      sha256 "f9785886b2c906b66294d0a2b3f0890e82a29927d696564f051c58c82b9a5a9c"

      def install
        bin.install "baton-google-bigquery"
      end
    end
  end

  on_linux do
    on_intel do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-google-bigquery/releases/download/v0.0.1/baton-google-bigquery-v0.0.1-linux-amd64.tar.gz"
        sha256 "40d0d6dd300f23c1d7a1fdfce329e8dbe92202c6b28eabc0914b2312e63b578d"

        def install
          bin.install "baton-google-bigquery"
        end
      end
    end
    on_arm do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-google-bigquery/releases/download/v0.0.1/baton-google-bigquery-v0.0.1-linux-arm64.tar.gz"
        sha256 "33c5b53a75ec152bbe6fe98b54bb716b4e54d84d08005d14c1f6eef77aebc014"

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