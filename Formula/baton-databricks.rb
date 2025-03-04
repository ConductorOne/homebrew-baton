# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonDatabricks < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.13"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/ConductorOne/baton-databricks/releases/download/v0.0.13/baton-databricks-v0.0.13-darwin-amd64.zip"
      sha256 "b705f78cb67414a48ece216c7423f59533c74fa3d3af75ca0b51144f47ac4c62"

      def install
        bin.install "baton-databricks"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/ConductorOne/baton-databricks/releases/download/v0.0.13/baton-databricks-v0.0.13-darwin-arm64.zip"
      sha256 "1c3a206b9f186f0bcdb673c3d36e20413a0ffaf7daeb139e6988aa461ce2a08f"

      def install
        bin.install "baton-databricks"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-databricks/releases/download/v0.0.13/baton-databricks-v0.0.13-linux-amd64.tar.gz"
        sha256 "40cca4141125378891109e519bf8f669e2dc74d5e460605f458da7bcf4c80aa1"

        def install
          bin.install "baton-databricks"
        end
      end
    end
    if Hardware::CPU.arm?
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-databricks/releases/download/v0.0.13/baton-databricks-v0.0.13-linux-arm64.tar.gz"
        sha256 "a45996230cac20dd4c9200ef48aba0567ea6fe94940e29fd8806011927cd5202"

        def install
          bin.install "baton-databricks"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-databricks -v"
  end
end
