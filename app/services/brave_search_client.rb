require "net/http"
require "json"
require "digest"
require "zlib"
require "stringio"

class BraveSearchClient
  API_BASE = "https://api.search.brave.com/res/v1/web/search"
  CACHE_TTL = 7.days
  MAX_RETRIES = 3

  # Class-level mutex and timestamp for rate limiting across instances
  @rate_mutex = Mutex.new
  @last_request_at = 0.0

  class << self
    attr_reader :rate_mutex
    attr_accessor :last_request_at

    def rate_limit_delay
      @rate_limit_delay ||= begin
        rps = ENV.fetch("BRAVE_SEARCH_RATE_LIMIT", "1").to_f
        rps > 0 ? (1.0 / rps) : 0
      end
    end
  end

  def initialize
    @api_key = ENV.fetch("BRAVE_SEARCH_API_KEY", "")
  end

  def search(query)
    cache_key = "brave:#{Digest::SHA256.hexdigest(query)}"
    cached = UrlScanResult.cached_result(cache_key, "brave_search")
    return cached_to_result(cached, query) if cached

    return nil if @api_key.blank?

    response = fetch_results(query)
    return nil unless response

    result = parse_response(response, query)
    cache_result(cache_key, result)
    result
  rescue => e
    Rails.logger.error("BraveSearchClient: Failed for '#{query}': #{e.message}")
    nil
  end

  private

  def fetch_results(query)
    uri = URI(API_BASE)
    uri.query = URI.encode_www_form(q: query, count: 10)

    retries = 0
    loop do
      wait_for_rate_limit

      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.open_timeout = 10
      http.read_timeout = 15

      request = Net::HTTP::Get.new(uri)
      request["Accept"] = "application/json"
      request["Accept-Encoding"] = "gzip"
      request["X-Subscription-Token"] = @api_key

      response = http.request(request)
      body = decompress(response)

      if response.code == "429" && retries < MAX_RETRIES
        retries += 1
        delay = [self.class.rate_limit_delay, 1.0].max * retries
        Rails.logger.info("BraveSearchClient: Rate limited (429), retry #{retries}/#{MAX_RETRIES} after #{delay}s")
        sleep(delay)
        next
      end

      unless response.is_a?(Net::HTTPSuccess)
        Rails.logger.error("BraveSearchClient: HTTP #{response.code} for '#{query}': #{body[0..200]}")
        return nil
      end

      return JSON.parse(body)
    end
  end

  def wait_for_rate_limit
    delay = self.class.rate_limit_delay
    return if delay <= 0

    self.class.rate_mutex.synchronize do
      now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      elapsed = now - self.class.last_request_at
      if elapsed < delay
        sleep(delay - elapsed)
      end
      self.class.last_request_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end
  end

  def decompress(response)
    if response["Content-Encoding"] == "gzip"
      Zlib::GzipReader.new(StringIO.new(response.body)).read
    else
      response.body
    end
  rescue Zlib::GzipFile::Error
    response.body
  end

  def parse_response(data, query)
    web_results = data.dig("web", "results") || []

    results = web_results.first(10).map do |r|
      {
        title: r["title"],
        url: r["url"],
        description: r["description"],
        age: r["age"],
        site_name: r.dig("meta_url", "hostname")
      }
    end

    {
      query: query,
      results: results,
      source: "brave_search"
    }
  end

  def cache_result(cache_key, result)
    UrlScanResult.find_or_initialize_by(url: cache_key, source: "brave_search").update!(
      domain: nil,
      malicious: false,
      detection_count: result[:results].size,
      scan_details: result,
      expires_at: CACHE_TTL.from_now
    )
  rescue ActiveRecord::RecordNotUnique, ActiveRecord::RecordInvalid
    UrlScanResult.find_by(url: cache_key, source: "brave_search")&.update(
      domain: nil,
      malicious: false,
      detection_count: result[:results].size,
      scan_details: result,
      expires_at: CACHE_TTL.from_now
    )
  end

  def cached_to_result(cached, query)
    details = cached.scan_details || {}
    {
      query: query,
      results: details["results"] || [],
      source: "brave_search",
      cached: true
    }
  end
end
