require "test_helper"

class TriageLlmConsultationJobTest < ActiveSupport::TestCase
  test "saves token usage from a RubyLLM 2.0 response through OpenRouter" do
    email = create(:email, :messenger_triage)
    response = Struct.new(:content, :tokens).new(
      { score: 25, verdict: "legitimate", confidence: 0.9, reasoning: "Test response" }.to_json,
      RubyLLM::Tokens.new(input: 80, output: 30)
    )
    chat = Object.new
    chat.define_singleton_method(:with_instructions) { |_instructions| self }
    chat.define_singleton_method(:ask) { |_prompt| response }
    chat_options = nil
    chat_factory = lambda do |**options|
      chat_options = options
      chat
    end

    original_chat = RubyLLM.method(:chat)
    original_finalize = Triage::LlmAnalyzer.method(:finalize)
    RubyLLM.define_singleton_method(:chat, chat_factory)
    Triage::LlmAnalyzer.define_singleton_method(:finalize) { |_email, _verdict| nil }
    begin
      TriageLlmConsultationJob.perform_now(email.id, "anthropic", "anthropic/claude-sonnet-4.6", "System", "User")
    ensure
      RubyLLM.define_singleton_method(:chat, original_chat)
      Triage::LlmAnalyzer.define_singleton_method(:finalize, original_finalize)
    end

    verdict = email.llm_verdicts.find_by!(provider: "anthropic")
    assert_equal :openrouter, chat_options[:provider]
    assert_equal true, chat_options[:assume_model_exists]
    assert_equal 25, verdict.score, verdict.reasoning
    assert_equal 80, verdict.prompt_tokens
    assert_equal 30, verdict.completion_tokens
  end
end
