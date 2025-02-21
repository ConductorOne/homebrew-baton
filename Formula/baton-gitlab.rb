# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonGitlab < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.5"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-gitlab/releases/download/v0.0.5/baton-gitlab-v0.0.5-darwin-amd64.zip"
      sha256 "1b1d6cb14f1a586c268a43685edc880ccd5352b81982a0840b892feefb98e396"

      def install
        bin.install "baton-gitlab"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-gitlab/releases/download/v0.0.5/baton-gitlab-v0.0.5-darwin-arm64.zip"
      sha256 "eb8f382a1bd71937c211ad4e33f01e857cdd373038fecdabe3bd253ce0d788a0"

      def install
        bin.install "baton-gitlab"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-gitlab/releases/download/v0.0.5/baton-gitlab-v0.0.5-linux-amd64.tar.gz"
        sha256 "9e1d4853bd4b441388c493ef6dad06cecea3c9f76c4025c2bc4f270c2354eae0"

        def install
          bin.install "baton-gitlab"
        end
      end
    end
    if Hardware::CPU.arm?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-gitlab/releases/download/v0.0.5/baton-gitlab-v0.0.5-linux-arm64.tar.gz"
        sha256 "e132cced01d50e76cce6c5731025abb1744c10ddb2fda775143af762c64596ff"

        def install
          bin.install "baton-gitlab"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-gitlab -v"
  end
end
