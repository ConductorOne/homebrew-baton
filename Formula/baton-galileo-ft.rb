# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonGalileoFt < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.2"

  on_macos do
    on_intel do
      url "https://github.com/ConductorOne/baton-galileo-ft/releases/download/v0.0.2/baton-galileo-ft-v0.0.2-darwin-amd64.zip"
      sha256 "363778e9c671d4a813745f185ddb787408cd8a0b88f8cf0f374cbe32cf5a7a24"

      def install
        bin.install "baton-galileo-ft"
      end
    end
    on_arm do
      url "https://github.com/ConductorOne/baton-galileo-ft/releases/download/v0.0.2/baton-galileo-ft-v0.0.2-darwin-arm64.zip"
      sha256 "c81f1ba57cc3e9d650191276f10a145571a0f741a534f4006fa3f93b9627f34a"

      def install
        bin.install "baton-galileo-ft"
      end
    end
  end

  on_linux do
    on_intel do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-galileo-ft/releases/download/v0.0.2/baton-galileo-ft-v0.0.2-linux-amd64.tar.gz"
        sha256 "9be5599c43359c60a02064bce6e2004fa828e3fa09c20092bacbe4862faf1735"

        def install
          bin.install "baton-galileo-ft"
        end
      end
    end
    on_arm do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-galileo-ft/releases/download/v0.0.2/baton-galileo-ft-v0.0.2-linux-arm64.tar.gz"
        sha256 "e8e05c3a92754a6c3c7c3e980e568fafbc751e669b889bced566c97ab94d0573"

        def install
          bin.install "baton-galileo-ft"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-galileo-ft -v"
  end
end
