require "test_helper"

class LlmConsultationJobTest < ActiveSupport::TestCase
  test "saves token usage from a RubyLLM 2.0 response through OpenRouter" do
    email = create(:email)
    response = Struct.new(:content, :tokens).new(
      { score: 75, verdict: "fraudulent", confidence: 0.8, reasoning: "Test response" }.to_json,
      RubyLLM::Tokens.new(input: 120, output: 45)
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
    RubyLLM.define_singleton_method(:chat, chat_factory)
    begin
      LlmConsultationJob.perform_now(email.id, "openai", "openai/gpt-5.4", "System", "User")
    ensure
      RubyLLM.define_singleton_method(:chat, original_chat)
    end

    verdict = email.llm_verdicts.find_by!(provider: "openai")
    assert_equal :openrouter, chat_options[:provider]
    assert_equal true, chat_options[:assume_model_exists]
    assert_equal 75, verdict.score, verdict.reasoning
    assert_equal 120, verdict.prompt_tokens
    assert_equal 45, verdict.completion_tokens
  end
end
