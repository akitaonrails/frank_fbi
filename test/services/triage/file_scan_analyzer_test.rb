require "test_helper"

class Triage::FileScanAnalyzerTest < ActiveSupport::TestCase
  test "analyze creates triage_file_scan layer with no attachments" do
    email = create(:email, :messenger_triage, attachments_info: [])

    analyzer = Triage::FileScanAnalyzer.new(email)
    layer = analyzer.analyze

    assert_equal "triage_file_scan", layer.layer_name
    assert_equal "completed", layer.status
    assert_equal 0.30, layer.weight
    assert_equal 0, layer.score
    assert_includes layer.explanation, "Nenhum anexo"
  end

  test "clean attachments produce zero score" do
    email = create(:email, :messenger_triage, attachments_info: [
      { "filename" => "document.pdf", "content_type" => "application/pdf", "size" => 1024, "sha256" => "abc123" }
    ])

    stub_request(:get, /virustotal.com/).to_return(
      status: 200,
      body: {
        data: { attributes: { last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 50, undetected: 10 } } }
      }.to_json,
      headers: { "Content-Type" => "application/json" }
    )

    analyzer = Triage::FileScanAnalyzer.new(email)
    layer = analyzer.analyze

    assert_equal 0, layer.score
    assert_includes layer.explanation, "nenhuma ameaça"
  end

  test "dangerous extension increases score" do
    email = create(:email, :messenger_triage, attachments_info: [
      { "filename" => "installer.exe", "content_type" => "application/octet-stream", "size" => 4096, "sha256" => "def456" }
    ])

    stub_request(:get, /virustotal.com/).to_return(
      status: 200,
      body: {
        data: { attributes: { last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 50, undetected: 10 } } }
      }.to_json,
      headers: { "Content-Type" => "application/json" }
    )

    analyzer = Triage::FileScanAnalyzer.new(email)
    layer = analyzer.analyze

    assert layer.score > 0, "Dangerous extension should increase score"
    assert_includes layer.explanation, "ameaça"
  end

  test "malicious file from VirusTotal increases score" do
    email = create(:email, :messenger_triage, attachments_info: [
      { "filename" => "photo.jpg", "content_type" => "image/jpeg", "size" => 2048, "sha256" => "malicious_hash" }
    ])

    stub_request(:get, /virustotal.com/).to_return(
      status: 200,
      body: {
        data: { attributes: { last_analysis_stats: { malicious: 10, suspicious: 2, harmless: 30, undetected: 8 } } }
      }.to_json,
      headers: { "Content-Type" => "application/json" }
    )

    analyzer = Triage::FileScanAnalyzer.new(email)
    layer = analyzer.analyze

    assert layer.score >= 30, "Malicious file should significantly increase score"
    assert_equal 1, layer.details["attachments_malicious_count"]
  end
end
