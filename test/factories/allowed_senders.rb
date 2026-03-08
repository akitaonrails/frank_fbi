FactoryBot.define do
  factory :allowed_sender do
    sequence(:email_address) { |n| "sender#{n}@example.com" }
    added_by { "admin@example.com" }
    active { true }

    trait :inactive do
      active { false }
    end
  end
end
