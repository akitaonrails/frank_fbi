FactoryBot.define do
  factory :analysis_layer do
    email
    layer_name { "header_auth" }
    weight { 0.15 }
    confidence { 1.0 }
    status { "pending" }

    trait :completed do
      status { "completed" }
      score { 50 }
      explanation { "Test explanation" }
    end

    trait :header_auth do
      layer_name { "header_auth" }
      weight { 0.20 }
    end

    trait :content_analysis do
      layer_name { "content_analysis" }
      weight { 0.25 }
    end

    trait :sender_reputation do
      layer_name { "sender_reputation" }
      weight { 0.20 }
    end

    trait :external_api do
      layer_name { "external_api" }
      weight { 0.20 }
    end

    trait :entity_verification do
      layer_name { "entity_verification" }
      weight { 0.05 }
    end

    trait :llm_analysis do
      layer_name { "llm_analysis" }
      weight { 0.10 }
    end
  end
end
