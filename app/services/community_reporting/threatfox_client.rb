require "net/http"
require "json"

module CommunityReporting
  class ThreatfoxClient
    API_BASE = "https://threatfox-api.abuse.ch/api/v1/"

    def initialize
      @api_key = ENV.fetch("THREATFOX_AUTH_KEY", "")
    end

    def submit_iocs(iocs, confidence:, reference: nil)
      return nil if @api_key.blank?

      payloads = build_payloads(iocs, confidence: confidence, reference: reference)
      return nil if payloads.empty?

      results = payloads.map { |payload| submit(payload) }
      results.compact
    rescue => e
      Rails.logger.error("ThreatfoxClient: Failed to submit IOCs: #{e.message}")
      nil
    end

    private

    def build_payloads(iocs, confidence:, reference:)
      entries = []

      iocs[:urls]&.each do |url|
        entries << { ioc: url, ioc_type: "url", threat_type: "payload_delivery" }
      end

      iocs[:domains]&.each do |domain|
        entries << { ioc: domain, ioc_type: "domain", threat_type: "payload_delivery" }
      end

      iocs[:ips]&.each do |ip|
        entries << { ioc: "#{ip}:25", ioc_type: "ip:port", threat_type: "payload_delivery" }
      end

      return [] if entries.empty?

      # ThreatFox accepts up to 100 IOCs per request
      entries.each_slice(100).map do |batch|
        {
          query: "submit_ioc",
          threat_type: "payload_delivery",
          ioc_type: batch.first[:ioc_type],
          malware: "Phishing",
          confidence_level: map_confidence(confidence),
          reference: reference,
          iocs: batch.map { |e| e[:ioc] }
        }
      end
    end

    def submit(payload)
      uri = URI(API_BASE)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true

      request = Net::HTTP::Post.new(uri)
      request["Auth-Key"] = @api_key
      request["Content-Type"] = "application/json"
      request.body = payload.to_json

      response = http.request(request)
      return nil unless response.is_a?(Net::HTTPSuccess)

      data = JSON.parse(response.body)
      { status: data["query_status"], data: data["data"] }
    end

    def map_confidence(internal_score)
      # ThreatFox uses 0-100 confidence, same as our internal score
      [[internal_score.to_i, 100].min, 0].max
    end
  end
end
