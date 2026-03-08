FactoryBot.define do
  factory :llm_verdict do
    email
    provider { "anthropic" }
    model_id { "anthropic/claude-sonnet-4-6" }
    score { 75 }
    verdict { "suspicious_likely_fraud" }
    reasoning { "Multiple indicators of fraud detected." }
    key_findings { ["Reply-To mismatch", "Authority impersonation", "Financial promises"] }
    confidence { 0.85 }
    prompt_tokens { 1000 }
    completion_tokens { 200 }
    response_time_seconds { 3.5 }
  end
end
