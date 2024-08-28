# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonAws < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.28"

  on_macos do
    on_intel do
      url "https://github.com/ConductorOne/baton-aws/releases/download/v0.0.28/baton-aws-v0.0.28-darwin-amd64.zip"
      sha256 "78efcf0c159a5b46cda0636406fa6eb0ca3c4934d9a60f1d3d247c601a786632"

      def install
        bin.install "baton-aws"
      end
    end
    on_arm do
      url "https://github.com/ConductorOne/baton-aws/releases/download/v0.0.28/baton-aws-v0.0.28-darwin-arm64.zip"
      sha256 "8f30cf9b64e60f3c29ff471a2f2398ebe0aff5557a96a0c4ed699867b4e915ca"

      def install
        bin.install "baton-aws"
      end
    end
  end

  on_linux do
    on_intel do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-aws/releases/download/v0.0.28/baton-aws-v0.0.28-linux-amd64.tar.gz"
        sha256 "8523451d316259116eee2848be40d370f74b7add9822bfbb81280e4e19b92172"

        def install
          bin.install "baton-aws"
        end
      end
    end
    on_arm do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-aws/releases/download/v0.0.28/baton-aws-v0.0.28-linux-arm64.tar.gz"
        sha256 "cd273f94e357ec4d10d195ef3e682f68aab93baf74adfc0759bfd45794985d9b"

        def install
          bin.install "baton-aws"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-aws -v"
  end
end
