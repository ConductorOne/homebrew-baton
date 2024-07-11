# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonSnyk < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.3"

  on_macos do
    on_intel do
      url "https://github.com/ConductorOne/baton-snyk/releases/download/v0.0.3/baton-snyk-v0.0.3-darwin-amd64.zip"
      sha256 "5dbe18a574dcd50877be99edb1025d7ece6b08db323ba7083eedea48cec32906"

      def install
        bin.install "baton-snyk"
      end
    end
    on_arm do
      url "https://github.com/ConductorOne/baton-snyk/releases/download/v0.0.3/baton-snyk-v0.0.3-darwin-arm64.zip"
      sha256 "dbf146733b85ed7a865f9565fb38964870cc62f424d31cad2dd32cd7c340f7b3"

      def install
        bin.install "baton-snyk"
      end
    end
  end

  on_linux do
    on_intel do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-snyk/releases/download/v0.0.3/baton-snyk-v0.0.3-linux-amd64.tar.gz"
        sha256 "3c9bb1fd7666f97ff4aa05d6e0f9758999f891f2693be3079fe7d6fcec612866"

        def install
          bin.install "baton-snyk"
        end
      end
    end
    on_arm do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-snyk/releases/download/v0.0.3/baton-snyk-v0.0.3-linux-arm64.tar.gz"
        sha256 "be5c7bf8fafac3b99313b9e4d59cd51904bb24eac160cdca559c08a2dd6cb528"

        def install
          bin.install "baton-snyk"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-snyk -v"
  end
end
