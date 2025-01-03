# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonAws < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.31"

  on_macos do
    on_intel do
      url "https://github.com/ConductorOne/baton-aws/releases/download/v0.0.31/baton-aws-v0.0.31-darwin-amd64.zip"
      sha256 "d622f987ae3f91d4115c733bb6bdefc7f32399ff47ffce360790efca585981be"

      def install
        bin.install "baton-aws"
      end
    end
    on_arm do
      url "https://github.com/ConductorOne/baton-aws/releases/download/v0.0.31/baton-aws-v0.0.31-darwin-arm64.zip"
      sha256 "87018a2f7d084294a3278a98c6f8e1faa311af44d5a586a7a61cefe5359e93f3"

      def install
        bin.install "baton-aws"
      end
    end
  end

  on_linux do
    on_intel do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-aws/releases/download/v0.0.31/baton-aws-v0.0.31-linux-amd64.tar.gz"
        sha256 "45c1325b15e25433f57e9009de7f32b82df402ce58a45bc5e674436ed306387c"

        def install
          bin.install "baton-aws"
        end
      end
    end
    on_arm do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-aws/releases/download/v0.0.31/baton-aws-v0.0.31-linux-arm64.tar.gz"
        sha256 "264a44097f5589a76ece04c6280402c7d4730f3c1cd368213d56897227df4c5e"

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
