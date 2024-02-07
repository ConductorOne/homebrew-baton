# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonJira < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.4"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-jira/releases/download/v0.0.4/baton-jira-v0.0.4-darwin-amd64.zip"
      sha256 "3a4843dc5c9858de0da34a75d06036681f34342eb5ea87bbfb4bc9ab8b33da7b"

      def install
        bin.install "baton-jira"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-jira/releases/download/v0.0.4/baton-jira-v0.0.4-darwin-arm64.zip"
      sha256 "4da57333697255662e3906d5c71cb8845628989d75cfd4c727002f5bd4d0cff3"

      def install
        bin.install "baton-jira"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-jira/releases/download/v0.0.4/baton-jira-v0.0.4-linux-arm64.tar.gz"
      sha256 "7f09eb5b9964eec3d612672c4b0e714cbac780c76d60a3e8f49f812384da807e"

      def install
        bin.install "baton-jira"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-jira/releases/download/v0.0.4/baton-jira-v0.0.4-linux-amd64.tar.gz"
      sha256 "b52f64092dae04d3ca94d34fa42daf00e99962fbc7f1e0f855c1d460dd79a37b"

      def install
        bin.install "baton-jira"
      end
    end
  end

  test do
    system "#{bin}/baton-jira -v"
  end
end
