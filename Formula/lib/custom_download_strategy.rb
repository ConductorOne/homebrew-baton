# This is based on the following, with minor fixes.
# https://github.com/Homebrew/brew/blob/193af1442f6b9a19fa71325160d0ee2889a1b6c9/Library/Homebrew/compat/download_strategy.rb#L48-L157

# BSD 2-Clause License
#
# Copyright (c) 2009-present, Homebrew contributors
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

class AbstractDownloadStrategyLocal
  extend Forwardable
  include FileUtils

  module Pourable
    def stage
      ohai "Pouring #{basename}"
      super
    end
  end

  attr_reader :cache, :cached_location, :url
  attr_reader :meta, :name, :version, :shutup
  private :meta, :name, :version, :shutup

  def initialize(url, name, version, **meta)
    @url = url
    @name = name
    @version = version
    @cache = meta.fetch(:cache, HOMEBREW_CACHE)
    @meta = meta
    @shutup = false
    extend Pourable if meta[:bottle]
  end

  # Download and cache the resource as {#cached_location}.
  def fetch; end

  # Suppress output
  def shutup!
    @shutup = true
  end

  def puts(*args)
    super(*args) unless shutup
  end

  def ohai(*args)
    super(*args) unless shutup
  end

  # Unpack {#cached_location} into the current working directory, and possibly
  # chdir into the newly-unpacked directory.
  # Unlike {Resource#stage}, this does not take a block.
  def stage
    UnpackStrategy.detect(cached_location,
                          extension_only: true,
                          ref_type: @ref_type, ref: @ref)
                  .extract_nestedly(basename: basename,
                                    extension_only: true,
                                    verbose: ARGV.verbose? && !shutup)
    chdir
  end

  def chdir
    entries = Dir["*"]
    case entries.length
    when 0 then raise "Empty archive"
    when 1 then begin
                  Dir.chdir entries.first
                rescue
                  nil
                end
    end
  end
  private :chdir

  # @!attribute [r] source_modified_time
  # Returns the most recent modified time for all files in the current working directory after stage.
  def source_modified_time
    Pathname.pwd.to_enum(:find).select(&:file?).map(&:mtime).max
  end

  # Remove {#cached_location} and any other files associated with the resource
  # from the cache.
  def clear_cache
    rm_rf(cached_location)
  end

  def basename
    cached_location.basename
  end

  private

  def system_command(*args, **options)
    super(*args, print_stderr: false, env: env, **options)
  end

  def system_command!(*args, **options)
    super(
      *args,
      print_stdout: !shutup,
      print_stderr: !shutup,
      verbose: ARGV.verbose? && !shutup,
      env: env,
      **options,
      )
  end

  def env
    {}
  end
end

class AbstractFileDownloadStrategyLocal < AbstractDownloadStrategy
  def temporary_path
    @temporary_path ||= Pathname.new("#{cached_location}.incomplete")
  end

  def symlink_location
    return @symlink_location if defined?(@symlink_location)

    ext = Pathname(parse_basename(url)).extname
    @symlink_location = @cache/"#{name}--#{version}#{ext}"
  end

  def cached_location
    return @cached_location if defined?(@cached_location)

    url_sha256 = Digest::SHA256.hexdigest(url)
    downloads = Pathname.glob(HOMEBREW_CACHE/"downloads/#{url_sha256}--*")
                        .reject { |path| path.extname.end_with?(".incomplete") }

    @cached_location = if downloads.count == 1
                         downloads.first
                       else
                         HOMEBREW_CACHE/"downloads/#{url_sha256}--#{resolved_basename}"
                       end
  end

  def basename
    cached_location.basename.sub(/^[\da-f]{64}\-\-/, "")
  end

  private

  def resolved_url
    resolved_url, = resolved_url_and_basename
    resolved_url
  end

  def resolved_basename
    _, resolved_basename = resolved_url_and_basename
    resolved_basename
  end

  def resolved_url_and_basename
    return @resolved_url_and_basename if defined?(@resolved_url_and_basename)

    @resolved_url_and_basename = [url, parse_basename(url)]
  end

  def parse_basename(url)
    uri_path = if URI::DEFAULT_PARSER.make_regexp =~ url
                 uri = URI(url)

                 if uri.query
                   query_params = CGI.parse(uri.query)
                   query_params["response-content-disposition"].each do |param|
                     query_basename = param[/attachment;\s*filename=(["']?)(.+)\1/i, 2]
                     return query_basename if query_basename
                   end
                 end

                 uri.query ? "#{uri.path}?#{uri.query}" : uri.path
               else
                 url
               end

    uri_path = URI.decode_www_form_component(uri_path)

    # We need a Pathname because we've monkeypatched extname to support double
    # extensions (e.g. tar.gz).
    # Given a URL like https://example.com/download.php?file=foo-1.0.tar.gz
    # the basename we want is "foo-1.0.tar.gz", not "download.php".
    Pathname.new(uri_path).ascend do |path|
      ext = path.extname[/[^?&]+/]
      return path.basename.to_s[/[^?&]+#{Regexp.escape(ext)}/] if ext
    end

    File.basename(uri_path)
  end
end

class CurlDownloadStrategyLocal < AbstractFileDownloadStrategyLocal
  attr_reader :mirrors

  def initialize(url, name, version, **meta)
    super
    @mirrors = meta.fetch(:mirrors, [])
  end

  def fetch
    download_lock = LockFile.new(temporary_path.basename)
    download_lock.lock

    urls = [url, *mirrors]

    begin
      url = urls.shift

      ohai "Downloading #{url}"

      if cached_location.exist?
        puts "Already downloaded: #{cached_location}"
      else
        begin
          resolved_url, = resolve_url_and_basename(url)

          _fetch(url: url, resolved_url: resolved_url)
        rescue ErrorDuringExecution
          raise CurlDownloadStrategyError, url
        end
        ignore_interrupts do
          cached_location.dirname.mkpath
          temporary_path.rename(cached_location)
          symlink_location.dirname.mkpath
        end
      end

      FileUtils.ln_s cached_location.relative_path_from(symlink_location.dirname), symlink_location, force: true
    rescue CurlDownloadStrategyError
      raise if urls.empty?

      puts "Trying a mirror..."
      retry
    end
  ensure
    download_lock.unlock
  end

  def clear_cache
    super
    rm_rf(temporary_path)
  end

  private

  def resolved_url_and_basename
    return @resolved_url_and_basename if defined?(@resolved_url_and_basename)

    @resolved_url_and_basename = resolve_url_and_basename(url)
  end

  def resolve_url_and_basename(url)
    if ENV["HOMEBREW_ARTIFACT_DOMAIN"]
      url = url.sub(%r{^((ht|f)tps?://)?}, ENV["HOMEBREW_ARTIFACT_DOMAIN"].chomp("/") + "/")
    end

    out, _, status= curl_output("--location", "--silent", "--head", url.to_s)

    lines = status.success? ? out.lines.map(&:chomp) : []

    locations = lines.map { |line| line[/^Location:\s*(.*)$/i, 1] }
                     .compact

    redirect_url = locations.reduce(url) do |current_url, location|
      if location.start_with?("//")
        uri = URI(current_url)
        "#{uri.scheme}:#{location}"
      elsif location.start_with?("/")
        uri = URI(current_url)
        "#{uri.scheme}://#{uri.host}#{location}"
      else
        location
      end
    end

    filenames = lines.map { |line| line[/^Content\-Disposition:\s*attachment;\s*filename=(["']?)([^;]+)\1/i, 2] }
                     .compact

    basename = filenames.last || parse_basename(redirect_url)

    [redirect_url, basename]
  end

  def _fetch(url:, resolved_url:)
    ohai "Downloading from #{resolved_url}" if url != resolved_url

    if ENV["HOMEBREW_NO_INSECURE_REDIRECT"] &&
      url.start_with?("https://") && !resolved_url.start_with?("https://")
      $stderr.puts "HTTPS to HTTP redirect detected & HOMEBREW_NO_INSECURE_REDIRECT is set."
      raise CurlDownloadStrategyError, url
    end

    curl_download resolved_url, to: temporary_path
  end

  # Curl options to be always passed to curl,
  # with raw head calls (`curl --head`) or with actual `fetch`.
  def _curl_args
    args = []

    if meta.key?(:cookies)
      escape_cookie = ->(cookie) { URI.encode_www_form([cookie]) }
      args += ["-b", meta.fetch(:cookies).map(&escape_cookie).join(";")]
    end

    args += ["-e", meta.fetch(:referer)] if meta.key?(:referer)

    args += ["--user", meta.fetch(:user)] if meta.key?(:user)

    args
  end

  def _curl_opts
    return { user_agent: meta.fetch(:user_agent) } if meta.key?(:user_agent)

    {}
  end

  def curl_output(*args, **options)
    super(*_curl_args, *args, **_curl_opts, **options)
  end

  def curl(*args, **options)
    args << "--connect-timeout" << "5" unless mirrors.empty?
    super(*_curl_args, *args, **_curl_opts, **options)
  end
end

# GitHubPrivateRepositoryDownloadStrategy downloads contents from GitHub
# Private Repository. To use it, add
# `:using => GitHubPrivateRepositoryDownloadStrategy` to the URL section of
# your formula. This download strategy uses GitHub access tokens (in the
# environment variables `HOMEBREW_GITHUB_API_TOKEN`) to sign the request.  This
# strategy is suitable for corporate use just like S3DownloadStrategy, because
# it lets you use a private GitHub repository for internal distribution.  It
# works with public one, but in that case simply use CurlDownloadStrategy.
class GitHubPrivateRepositoryDownloadStrategy < CurlDownloadStrategyLocal
  require "utils/formatter"
  require "utils/github"

  def initialize(url, name, version, **meta)
    super
    parse_url_pattern
    set_github_token
  end

  def parse_url_pattern
    unless match = url.match(%r{https://github.com/([^/]+)/([^/]+)/(\S+)})
      raise CurlDownloadStrategyError, "Invalid url pattern for GitHub Repository."
    end

    _, @owner, @repo, @filepath = *match
  end

  def download_url
    "https://#{@github_token}@github.com/#{@owner}/#{@repo}/#{@filepath}"
  end

  private

  def _fetch(url:, resolved_url:, timeout:)
    curl_download download_url, to: temporary_path
  end

  def set_github_token
    @github_token = ENV["HOMEBREW_GITHUB_API_TOKEN"]
    unless @github_token
      raise CurlDownloadStrategyError, "Environmental variable HOMEBREW_GITHUB_API_TOKEN is required."
    end

    validate_github_repository_access!
  end

  def validate_github_repository_access!
    # Test access to the repository
    GitHub.repository(@owner, @repo)
  rescue GitHub::API::HTTPNotFoundError
    # We switched to GitHub::API::HTTPNotFoundError,
    # because we can now handle bad credentials messages
    message = <<~EOS
      HOMEBREW_GITHUB_API_TOKEN can not access the repository: #{@owner}/#{@repo}
      This token may not have permission to access the repository or the url of formula may be incorrect.
    EOS
    raise CurlDownloadStrategyError, message
  end
end

# GitHubPrivateRepositoryReleaseDownloadStrategy downloads tarballs from GitHub
# Release assets. To use it, add
# `:using => GitHubPrivateRepositoryReleaseDownloadStrategy` to the URL section of
# your formula. This download strategy uses GitHub access tokens (in the
# environment variables HOMEBREW_GITHUB_API_TOKEN) to sign the request.
class GitHubPrivateRepositoryReleaseDownloadStrategy < GitHubPrivateRepositoryDownloadStrategy
  def initialize(url, name, version, **meta)
    super
  end

  def parse_url_pattern
    url_pattern = %r{https://github.com/([^/]+)/([^/]+)/releases/download/([^/]+)/(\S+)}
    unless @url =~ url_pattern
      raise CurlDownloadStrategyError, "Invalid url pattern for GitHub Release."
    end

    _, @owner, @repo, @tag, @filename = *@url.match(url_pattern)
  end

  def download_url
    "https://#{@github_token}@api.github.com/repos/#{@owner}/#{@repo}/releases/assets/#{asset_id}"
  end

  private

  def _fetch(url:, resolved_url:, timeout:)
    # HTTP request header `Accept: application/octet-stream` is required.
    # Without this, the GitHub API will respond with metadata, not binary.
    curl_download download_url, "--header", "Accept: application/octet-stream", to: temporary_path
  end

  def asset_id
    @asset_id ||= resolve_asset_id
  end

  def resolve_asset_id
    release_metadata = fetch_release_metadata
    assets = release_metadata["assets"].select { |a| a["name"] == @filename }
    raise CurlDownloadStrategyError, "Asset file not found." if assets.empty?

    assets.first["id"]
  end

  def fetch_release_metadata
    #release_url = "https://api.github.com/repos/#{@owner}/#{@repo}/releases/tags/#{@tag}"
    #GitHub::API.open_rest(release_url)
    GitHub.get_release(@owner, @repo, @tag)
  end
end

class DownloadStrategyDetector
  class << self
    module Compat
      def detect_from_url(url)
        case url
        when %r{^s3://}
          odisabled("s3://",
                    "a vendored S3DownloadStrategy in your own formula or tap (using require_relative)")
          S3DownloadStrategy
        when %r{^scp://}
          odisabled("scp://",
                    "a vendored ScpDownloadStrategy in your own formula or tap (using require_relative)")
          ScpDownloadStrategy
        else
          super(url)
        end
      end

      def detect_from_symbol(symbol)
        case symbol
        when :github_private_repo
          GitHubPrivateRepositoryDownloadStrategy
        when :github_private_release
          GitHubPrivateRepositoryReleaseDownloadStrategy
        when :s3
          odisabled(":s3",
                    "a vendored S3DownloadStrategy in your own formula or tap (using require_relative)")
          S3DownloadStrategy
        when :scp
          odisabled(":scp",
                    "a vendored ScpDownloadStrategy in your own formula or tap (using require_relative)")
          ScpDownloadStrategy
        else
          super(symbol)
        end
      end
    end

    prepend Compat
  end
end