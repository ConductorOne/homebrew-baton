# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonOkta < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.1.14"

  on_macos do
    on_intel do
      url "https://github.com/ConductorOne/baton-okta/releases/download/v0.1.14/baton-okta-v0.1.14-darwin-amd64.zip"
      sha256 "300477b174a55d37c18e18a2edd231ba4589d1ebdd572a99cbcfbe676ac25374"

      def install
        bin.install "baton-okta"
      end
    end
    on_arm do
      url "https://github.com/ConductorOne/baton-okta/releases/download/v0.1.14/baton-okta-v0.1.14-darwin-arm64.zip"
      sha256 "694ffd9c73f1491f1d4053db54fff9fdfffbf44a959d8ed0c1838bbd331bb766"

      def install
        bin.install "baton-okta"
      end
    end
  end

  on_linux do
    on_intel do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-okta/releases/download/v0.1.14/baton-okta-v0.1.14-linux-amd64.tar.gz"
        sha256 "ae48cb0094f765922e13a554b9b3fd51cb723abaafacedacc472cc536723a756"

        def install
          bin.install "baton-okta"
        end
      end
    end
    on_arm do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-okta/releases/download/v0.1.14/baton-okta-v0.1.14-linux-arm64.tar.gz"
        sha256 "3b34c5f9137d434ae1abe5b33ddc52b88021266532a766820d520fbc19f8a6b1"

        def install
          bin.install "baton-okta"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-okta -v"
  end
end
