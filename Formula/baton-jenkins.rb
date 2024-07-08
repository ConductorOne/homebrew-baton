# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonJenkins < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.1"

  on_macos do
    on_intel do
      url "https://github.com/ConductorOne/baton-jenkins/releases/download/v0.0.1/baton-jenkins-v0.0.1-darwin-amd64.zip"
      sha256 "2f6d22497a579650af29dc0dee7a88a0d4043f5d71ef9328711f65be2fb15d4a"

      def install
        bin.install "baton-jenkins"
      end
    end
    on_arm do
      url "https://github.com/ConductorOne/baton-jenkins/releases/download/v0.0.1/baton-jenkins-v0.0.1-darwin-arm64.zip"
      sha256 "cf50aac7db6f388c501b634a9c5f3db64b90377b1aff697bf40e32056725496f"

      def install
        bin.install "baton-jenkins"
      end
    end
  end

  on_linux do
    on_intel do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-jenkins/releases/download/v0.0.1/baton-jenkins-v0.0.1-linux-amd64.tar.gz"
        sha256 "afd58830d98c401f2b1ebfaba1b972757d79c26996e56c2a30e42370321b461f"

        def install
          bin.install "baton-jenkins"
        end
      end
    end
    on_arm do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-jenkins/releases/download/v0.0.1/baton-jenkins-v0.0.1-linux-arm64.tar.gz"
        sha256 "f1e6ff7d313cf7ed7c7ffc43edd0271a6280437b988f68bb6653861c945f5c6f"

        def install
          bin.install "baton-jenkins"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-jenkins -v"
  end
end
