require "test_helper"

class VirusTotalClientTest < ActiveSupport::TestCase
  setup do
    ENV["VIRUSTOTAL_API_KEY"] = "test-api-key"
    @client = VirusTotalClient.new
    @sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  end

  teardown do
    ENV["VIRUSTOTAL_API_KEY"] = ""
  end

  test "scan_file_hash returns cached result when fresh cache exists" do
    UrlScanResult.create!(
      url: "sha256:#{@sha256}",
      source: "virustotal_file",
      malicious: true,
      detection_count: 5,
      scan_details: { hash: @sha256, malicious: true },
      expires_at: 1.hour.from_now
    )

    result = @client.scan_file_hash(@sha256)

    assert result[:cached]
    assert result[:malicious]
    assert_equal 5, result[:detection_count]
    assert_equal @sha256, result[:hash]
    assert_equal "virustotal_file", result[:source]
  end

  test "scan_file_hash calls API and caches result" do
    stub_request(:get, "https://www.virustotal.com/api/v3/files/#{@sha256}")
      .with(headers: { "x-apikey" => "test-api-key" })
      .to_return(
        status: 200,
        body: {
          data: {
            attributes: {
              last_analysis_stats: {
                "malicious" => 12,
                "suspicious" => 2,
                "harmless" => 50,
                "undetected" => 10
              }
            }
          }
        }.to_json,
        headers: { "Content-Type" => "application/json" }
      )

    result = @client.scan_file_hash(@sha256)

    assert result[:malicious]
    assert_equal 14, result[:detection_count]
    assert_equal 74, result[:total_scanners]
    assert_equal "virustotal_file", result[:source]

    # Verify cached
    cached = UrlScanResult.find_by(url: "sha256:#{@sha256}", source: "virustotal_file")
    assert cached.present?
    assert cached.malicious
    assert_equal 14, cached.detection_count
  end

  test "scan_file_hash returns nil when API key is blank" do
    ENV["VIRUSTOTAL_API_KEY"] = ""
    client = VirusTotalClient.new

    result = client.scan_file_hash(@sha256)
    assert_nil result
  end

  test "scan_file_hash returns nil on API error" do
    stub_request(:get, "https://www.virustotal.com/api/v3/files/#{@sha256}")
      .to_return(status: 404)

    result = @client.scan_file_hash(@sha256)
    assert_nil result
  end

  test "scan_file_hash handles clean file" do
    stub_request(:get, "https://www.virustotal.com/api/v3/files/#{@sha256}")
      .to_return(
        status: 200,
        body: {
          data: {
            attributes: {
              last_analysis_stats: {
                "malicious" => 0,
                "suspicious" => 0,
                "harmless" => 60,
                "undetected" => 5
              }
            }
          }
        }.to_json,
        headers: { "Content-Type" => "application/json" }
      )

    result = @client.scan_file_hash(@sha256)

    assert_not result[:malicious]
    assert_equal 0, result[:detection_count]
    assert_equal 65, result[:total_scanners]
  end

  test "scan_file_hash handles network exception gracefully" do
    stub_request(:get, "https://www.virustotal.com/api/v3/files/#{@sha256}")
      .to_raise(Errno::ECONNREFUSED)

    result = @client.scan_file_hash(@sha256)
    assert_nil result
  end
end
