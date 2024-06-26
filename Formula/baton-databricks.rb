# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonDatabricks < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.2"

  on_macos do
    on_intel do
      url "https://github.com/ConductorOne/baton-databricks/releases/download/v0.0.2/baton-databricks-v0.0.2-darwin-amd64.zip"
      sha256 "b3decf6133af3a34dd119d4a5901dbf4c9028e58a155ebbf9d37f7680282d8c6"

      def install
        bin.install "baton-databricks"
      end
    end
    on_arm do
      url "https://github.com/ConductorOne/baton-databricks/releases/download/v0.0.2/baton-databricks-v0.0.2-darwin-arm64.zip"
      sha256 "df37e4bffcce43334b20934933fc7ed10ed47f9e20a87ba27d02535f0468eeca"

      def install
        bin.install "baton-databricks"
      end
    end
  end

  on_linux do
    on_intel do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-databricks/releases/download/v0.0.2/baton-databricks-v0.0.2-linux-amd64.tar.gz"
        sha256 "c0f8cf64f0b9b47dabc281ab80ec8b53b71214deb9942f05c2670f913eeacc06"

        def install
          bin.install "baton-databricks"
        end
      end
    end
    on_arm do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-databricks/releases/download/v0.0.2/baton-databricks-v0.0.2-linux-arm64.tar.gz"
        sha256 "868b906edc3dba98483be83a71dc8530ea03384b73477a25d38d0f2c4d7cfb8f"

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
