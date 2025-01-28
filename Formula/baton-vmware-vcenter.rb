# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class BatonVmwareVcenter < Formula
  desc ""
  homepage "https://conductorone.com"
  version "0.0.1"

  on_macos do
    on_intel do
      url "https://github.com/ConductorOne/baton-vmware-vcenter/releases/download/v0.0.1/baton-vmware-vcenter-v0.0.1-darwin-amd64.zip"
      sha256 "a9082f9f63bbdcec2221aa82339362c4bed7ef6d4499a1de70353d0639744465"

      def install
        bin.install "baton-vmware-vcenter"
      end
    end
    on_arm do
      url "https://github.com/ConductorOne/baton-vmware-vcenter/releases/download/v0.0.1/baton-vmware-vcenter-v0.0.1-darwin-arm64.zip"
      sha256 "bfb5902bc4f80ffcd9726ba20111eebb94f07826fe8ec60d7c6af01bb6ef0e48"

      def install
        bin.install "baton-vmware-vcenter"
      end
    end
  end

  on_linux do
    on_intel do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-vmware-vcenter/releases/download/v0.0.1/baton-vmware-vcenter-v0.0.1-linux-amd64.tar.gz"
        sha256 "b1ef67d029433fc32069a24b9f381accf9939d13469beff750982ccecb45aad6"

        def install
          bin.install "baton-vmware-vcenter"
        end
      end
    end
    on_arm do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/ConductorOne/baton-vmware-vcenter/releases/download/v0.0.1/baton-vmware-vcenter-v0.0.1-linux-arm64.tar.gz"
        sha256 "2e7c5a75b02ed4d812611d7398ae85ebafb606849d93bc121f1f21486e20680c"

        def install
          bin.install "baton-vmware-vcenter"
        end
      end
    end
  end

  test do
    system "#{bin}/baton-vmware-vcenter -v"
  end
end
