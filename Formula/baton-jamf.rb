# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonJamf < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.6"

  on_macos do
    on_intel do
      url "https://github.com/ConductorOne/baton-jamf/releases/download/v0.0.6/baton-jamf-v0.0.6-darwin-amd64.zip"
      sha256 "b5a36514439e7cf8e28b7d0700a6a526bc29b850e7bd778ef904eac741a22e2b"

      def install
        bin.install "baton-jamf"
      end
    end
    on_arm do
      url "https://github.com/ConductorOne/baton-jamf/releases/download/v0.0.6/baton-jamf-v0.0.6-darwin-arm64.zip"
      sha256 "d7d6bf2ac870ffd958cc4cfbc8e8ecaaa6bc0d3292a5fc8ad43ea1178b9db162"

      def install
        bin.install "baton-jamf"
      end
    end
  end

  on_linux do
    on_intel do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-jamf/releases/download/v0.0.6/baton-jamf-v0.0.6-linux-amd64.tar.gz"
        sha256 "7078e3a06a83aabdf21734a64663e95a16f05a6b770aacdf99230506bdb7f0a7"

        def install
          bin.install "baton-jamf"
        end
      end
    end
    on_arm do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-jamf/releases/download/v0.0.6/baton-jamf-v0.0.6-linux-arm64.tar.gz"
        sha256 "a2157564d9d500cd5b1b74ffcaa5156b3cba881c6b07b89192e9a029bc62cd3f"

        def install
          bin.install "baton-jamf"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-jamf -v"
  end
end
