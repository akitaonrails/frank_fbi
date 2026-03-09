require "net/http"
require "json"
require "digest"
require "zlib"
require "stringio"

class BraveSearchClient
  API_BASE = "https://api.search.brave.com/res/v1/web/search"
  CACHE_TTL = 7.days

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

    unless response.is_a?(Net::HTTPSuccess)
      Rails.logger.error("BraveSearchClient: HTTP #{response.code} for '#{query}': #{body[0..200]}")
      return nil
    end

    JSON.parse(body)
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
