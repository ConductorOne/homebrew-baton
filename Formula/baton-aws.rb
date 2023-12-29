# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonAws < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.14"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-aws/releases/download/v0.0.14/baton-aws-v0.0.14-darwin-amd64.zip"
      sha256 "7ed13ca87b7edb2851258b301d389198d37c83d7104d18a9cca08ad6b41d796a"

      def install
        bin.install "baton-aws"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-aws/releases/download/v0.0.14/baton-aws-v0.0.14-darwin-arm64.zip"
      sha256 "fe7b628524d2f32fb619b7ab78cc8f10bf75a62f472b8fd6569e00c08116fc94"

      def install
        bin.install "baton-aws"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-aws/releases/download/v0.0.14/baton-aws-v0.0.14-linux-arm64.tar.gz"
      sha256 "d647e7f6ef29c398ebfe1fe4ced5ea153e4b9508789ff4bc05d7f1a12eb2856c"

      def install
        bin.install "baton-aws"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-aws/releases/download/v0.0.14/baton-aws-v0.0.14-linux-amd64.tar.gz"
      sha256 "d8bb5ac02d2f610b7482fa1bb63e9cd5a9de6864e7a2b758d9da9313445828b8"

      def install
        bin.install "baton-aws"
      end
    end
  end

  test do
    system "#{bin}/baton-aws -v"
  end
end
