# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonSalesforce < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.1"

  on_macos do
    on_intel do
      url "https://github.com/ConductorOne/baton-salesforce/releases/download/v0.0.1/baton-salesforce-v0.0.1-darwin-amd64.zip"
      sha256 "564a99a92030ee196c7b2d40898a9acf02cc3aaf184be39ba51eab0addbb1c47"

      def install
        bin.install "baton-salesforce"
      end
    end
    on_arm do
      url "https://github.com/ConductorOne/baton-salesforce/releases/download/v0.0.1/baton-salesforce-v0.0.1-darwin-arm64.zip"
      sha256 "5170da4e2e2331feb733d63e129f31fce830b0f59b360deb13ad96c88059715a"

      def install
        bin.install "baton-salesforce"
      end
    end
  end

  on_linux do
    on_intel do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-salesforce/releases/download/v0.0.1/baton-salesforce-v0.0.1-linux-amd64.tar.gz"
        sha256 "a2e9c846cb8d88ce764ac972a9a943d41a82ca59e8bad3123b531b598a90c7f1"

        def install
          bin.install "baton-salesforce"
        end
      end
    end
    on_arm do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-salesforce/releases/download/v0.0.1/baton-salesforce-v0.0.1-linux-arm64.tar.gz"
        sha256 "eff83b949b8d793e913b438b31a611ee93b519bf83c76481eee1d83a032c5d0e"

        def install
          bin.install "baton-salesforce"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-salesforce -v"
  end
end