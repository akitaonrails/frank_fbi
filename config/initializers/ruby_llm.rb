RubyLLM.configure do |config|
  config.openrouter_api_key = ENV.fetch("OPENROUTER_API_KEY", "")
end

# Register models not yet in ruby_llm's bundled registry.
# Based on existing registry entries for the same family.
Rails.application.config.after_initialize do
  missing_models = [
    {
      id: "openai/gpt-5.4",
      name: "OpenAI: GPT-5.4",
      provider: "openrouter",
      family: "openai",
      created_at: "2026-03-05 00:00:00 UTC",
      context_window: 1_000_000,
      max_output_tokens: 128_000,
      modalities: { input: %w[text image file], output: %w[text] },
      capabilities: %w[streaming function_calling structured_output],
      pricing: { text_tokens: { standard: { input_per_million: 2.5, output_per_million: 15.0, cached_input_per_million: 0.25 } } },
      metadata: { source: "manual" }
    }
  ]

  missing_models.each do |model_data|
    next if RubyLLM::Models.instance.any? { |m| m.id == model_data[:id] && m.provider == model_data[:provider] }

    model = RubyLLM::Model::Info.new(model_data)
    RubyLLM::Models.instance.all << model
  end
end
