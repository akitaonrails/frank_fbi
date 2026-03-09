require "test_helper"

class EntityVerificationJobTest < ActiveSupport::TestCase
  test "job is queued to external_api queue" do
    assert_equal "external_api", EntityVerificationJob.new.queue_name
  end

  test "job invokes analyzer for email" do
    email = create(:email)
    create(:analysis_layer, :completed, :header_auth, email: email, score: 50)
    create(:analysis_layer, :completed, :content_analysis, email: email, score: 50)

    # Stub WHOIS API for domain verification
    stub_request(:get, /whoisxmlapi\.com/).to_return(
      status: 200,
      body: {
        WhoisRecord: {
          registryData: { createdDate: 2.years.ago.iso8601 },
          registrarName: "Test Registrar"
        }
      }.to_json,
      headers: { "Content-Type" => "application/json" }
    )

    # Stub the LLM chat to avoid real API calls
    response = Struct.new(:content, :input_tokens, :output_tokens).new(
      { score: 50, confidence: 0.5, verdict_summary: "Test" }.to_json, 100, 50
    )
    chat = Object.new
    chat.define_singleton_method(:with_tool) { |_tool| self }
    chat.define_singleton_method(:ask) { |_prompt| response }

    # Patch RubyLLM.chat at module level for this test
    original_chat = RubyLLM.method(:chat)
    RubyLLM.define_singleton_method(:chat) { |**_opts| chat }

    begin
      EntityVerificationJob.perform_now(email.id)

      layer = email.analysis_layers.find_by(layer_name: "entity_verification")
      assert_not_nil layer
      assert_equal "completed", layer.status
    ensure
      RubyLLM.define_singleton_method(:chat, original_chat)
    end
  end
end
