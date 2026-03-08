class CreateEmails < ActiveRecord::Migration[8.1]
  def change
    create_table :emails do |t|
      t.string :message_id, null: false
      t.string :subject
      t.string :from_address
      t.string :from_name
      t.string :reply_to_address
      t.string :sender_domain
      t.string :submitter_email, null: false
      t.text :body_text
      t.text :body_html
      t.text :raw_headers
      t.text :raw_source
      t.json :extracted_urls, default: []
      t.json :extracted_emails, default: []
      t.json :attachments_info, default: []
      t.string :status, null: false, default: "pending"
      t.integer :final_score
      t.string :verdict
      t.text :verdict_explanation
      t.datetime :received_at
      t.datetime :analyzed_at

      t.timestamps
    end

    add_index :emails, :message_id, unique: true
    add_index :emails, :from_address
    add_index :emails, :sender_domain
    add_index :emails, :status
    add_index :emails, :verdict
    add_index :emails, :submitter_email
  end
end
