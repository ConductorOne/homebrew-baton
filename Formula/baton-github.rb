# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonGithub < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.1.28"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-github/releases/download/v0.1.28/baton-github-v0.1.28-darwin-amd64.zip"
      sha256 "878393cc5c233d63b026850d4dd631128b46a2845e433e534cdcd9f72231c0ca"

      def install
        bin.install "baton-github"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-github/releases/download/v0.1.28/baton-github-v0.1.28-darwin-arm64.zip"
      sha256 "9b98cdda9a5676ef0eb7cb6a5482991fdd5ceaf609c6ba596231e3a51ba80c6b"

      def install
        bin.install "baton-github"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-github/releases/download/v0.1.28/baton-github-v0.1.28-linux-amd64.tar.gz"
        sha256 "9107b9c52496f56ae3981dce393112be2ada3c56bfac091dd38ebf25abee5c53"

        def install
          bin.install "baton-github"
        end
      end
    end
    if Hardware::CPU.arm?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-github/releases/download/v0.1.28/baton-github-v0.1.28-linux-arm64.tar.gz"
        sha256 "48986a0be7c1317faeec32eb7e683a7ba17f705a35493cdc339d80fa40e1649f"

        def install
          bin.install "baton-github"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-github -v"
  end
end
