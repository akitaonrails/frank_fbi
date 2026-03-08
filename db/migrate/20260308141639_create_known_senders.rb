class CreateKnownSenders < ActiveRecord::Migration[8.1]
  def change
    create_table :known_senders do |t|
      t.string :email_address, null: false
      t.references :known_domain, foreign_key: true
      t.integer :emails_analyzed, default: 0
      t.integer :fraud_count, default: 0
      t.integer :legit_count, default: 0

      t.timestamps
    end

    add_index :known_senders, :email_address, unique: true
  end
end
