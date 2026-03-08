class CreateKnownDomains < ActiveRecord::Migration[8.1]
  def change
    create_table :known_domains do |t|
      t.string :domain, null: false
      t.string :category
      t.integer :reputation_score
      t.json :whois_data, default: {}
      t.integer :domain_age_days
      t.json :blacklist_results, default: {}
      t.integer :times_seen, default: 0
      t.integer :times_flagged_fraud, default: 0
      t.integer :times_flagged_legit, default: 0
      t.datetime :whois_checked_at
      t.datetime :blacklist_checked_at

      t.timestamps
    end

    add_index :known_domains, :domain, unique: true
    add_index :known_domains, :reputation_score
  end
end
