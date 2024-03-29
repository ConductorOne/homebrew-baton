# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonServicenow < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.3"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-servicenow/releases/download/v0.0.3/baton-servicenow-v0.0.3-darwin-amd64.zip"
      sha256 "c0f48c83ea4f5d5e91fee2e2d418e94b48610edef4d2d9d2ef209d9e9f563edb"

      def install
        bin.install "baton-servicenow"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-servicenow/releases/download/v0.0.3/baton-servicenow-v0.0.3-darwin-arm64.zip"
      sha256 "fcfdc39808aaa18b105084a7e4a0b39c060ae84db6f9f51dd728037890461b7f"

      def install
        bin.install "baton-servicenow"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ConductorOne/baton-servicenow/releases/download/v0.0.3/baton-servicenow-v0.0.3-linux-arm64.tar.gz"
      sha256 "df77728ca6a1840bfb21bdaaf2d4618527761c59eba39884f6d2be181cb10a62"

      def install
        bin.install "baton-servicenow"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-servicenow/releases/download/v0.0.3/baton-servicenow-v0.0.3-linux-amd64.tar.gz"
      sha256 "eda89df6a5e813b5a4e98d4f699fff5a26c3f085cb29fbb1b21c870cb6755b91"

      def install
        bin.install "baton-servicenow"
      end
    end
  end

  test do
    system "#{bin}/baton-servicenow -v"
  end
end
