# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# This file is the source Rails uses to define your schema when running `bin/rails
# db:schema:load`. When creating a new database, `bin/rails db:schema:load` tends to
# be faster and is potentially less error prone than running all of your
# migrations from scratch. Old migrations may fail to apply correctly if those
# migrations use external dependencies or application code.
#
# It's strongly recommended that you check this file into your version control system.

ActiveRecord::Schema[8.1].define(version: 2026_03_09_150337) do
  create_table "action_mailbox_inbound_emails", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.string "message_checksum", null: false
    t.string "message_id", null: false
    t.integer "status", default: 0, null: false
    t.datetime "updated_at", null: false
    t.index ["message_id", "message_checksum"], name: "index_action_mailbox_inbound_emails_uniqueness", unique: true
  end

  create_table "active_storage_attachments", force: :cascade do |t|
    t.bigint "blob_id", null: false
    t.datetime "created_at", null: false
    t.string "name", null: false
    t.bigint "record_id", null: false
    t.string "record_type", null: false
    t.index ["blob_id"], name: "index_active_storage_attachments_on_blob_id"
    t.index ["record_type", "record_id", "name", "blob_id"], name: "index_active_storage_attachments_uniqueness", unique: true
  end

  create_table "active_storage_blobs", force: :cascade do |t|
    t.bigint "byte_size", null: false
    t.string "checksum"
    t.string "content_type"
    t.datetime "created_at", null: false
    t.string "filename", null: false
    t.string "key", null: false
    t.text "metadata"
    t.string "service_name", null: false
    t.index ["key"], name: "index_active_storage_blobs_on_key", unique: true
  end

  create_table "active_storage_variant_records", force: :cascade do |t|
    t.bigint "blob_id", null: false
    t.string "variation_digest", null: false
    t.index ["blob_id", "variation_digest"], name: "index_active_storage_variant_records_uniqueness", unique: true
  end

  create_table "allowed_senders", force: :cascade do |t|
    t.boolean "active", default: true
    t.string "added_by"
    t.datetime "created_at", null: false
    t.string "email_address", null: false
    t.datetime "updated_at", null: false
    t.index ["email_address"], name: "index_allowed_senders_on_email_address", unique: true
  end

  create_table "analysis_layers", force: :cascade do |t|
    t.float "confidence", default: 1.0
    t.datetime "created_at", null: false
    t.json "details", default: {}
    t.integer "email_id", null: false
    t.text "explanation"
    t.string "layer_name", null: false
    t.integer "score"
    t.string "status", default: "pending", null: false
    t.datetime "updated_at", null: false
    t.float "weight", null: false
    t.index ["email_id", "layer_name"], name: "index_analysis_layers_on_email_id_and_layer_name", unique: true
    t.index ["email_id"], name: "index_analysis_layers_on_email_id"
  end

  create_table "analysis_reports", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.integer "email_id", null: false
    t.string "reply_message_id"
    t.text "report_html"
    t.text "report_text"
    t.datetime "sent_at"
    t.string "status", default: "pending", null: false
    t.datetime "updated_at", null: false
    t.index ["email_id"], name: "index_analysis_reports_on_email_id", unique: true
  end

  create_table "community_reports", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.json "details", default: {}
    t.integer "email_id", null: false
    t.json "iocs_submitted", default: {}
    t.json "providers", default: []
    t.datetime "updated_at", null: false
    t.index ["email_id"], name: "index_community_reports_on_email_id", unique: true
  end

  create_table "emails", force: :cascade do |t|
    t.datetime "analyzed_at"
    t.json "attachments_info", default: []
    t.text "body_html"
    t.text "body_text"
    t.datetime "created_at", null: false
    t.json "extracted_emails", default: []
    t.json "extracted_urls", default: []
    t.integer "final_score"
    t.string "from_address"
    t.string "from_name"
    t.string "message_id", null: false
    t.string "pipeline_type", default: "fraud_analysis", null: false
    t.text "raw_headers"
    t.text "raw_source"
    t.datetime "received_at"
    t.string "reply_to_address"
    t.string "sender_domain"
    t.string "status", default: "pending", null: false
    t.string "subject"
    t.string "submitter_email", null: false
    t.datetime "updated_at", null: false
    t.string "verdict"
    t.text "verdict_explanation"
    t.index ["from_address"], name: "index_emails_on_from_address"
    t.index ["message_id"], name: "index_emails_on_message_id", unique: true
    t.index ["pipeline_type"], name: "index_emails_on_pipeline_type"
    t.index ["sender_domain"], name: "index_emails_on_sender_domain"
    t.index ["status"], name: "index_emails_on_status"
    t.index ["submitter_email"], name: "index_emails_on_submitter_email"
    t.index ["verdict"], name: "index_emails_on_verdict"
  end

  create_table "known_domains", force: :cascade do |t|
    t.datetime "blacklist_checked_at"
    t.json "blacklist_results", default: {}
    t.string "category"
    t.datetime "created_at", null: false
    t.string "domain", null: false
    t.integer "domain_age_days"
    t.integer "reputation_score"
    t.integer "times_flagged_fraud", default: 0
    t.integer "times_flagged_legit", default: 0
    t.integer "times_seen", default: 0
    t.datetime "updated_at", null: false
    t.datetime "whois_checked_at"
    t.json "whois_data", default: {}
    t.index ["domain"], name: "index_known_domains_on_domain", unique: true
    t.index ["reputation_score"], name: "index_known_domains_on_reputation_score"
  end

  create_table "known_senders", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.string "email_address", null: false
    t.integer "emails_analyzed", default: 0
    t.integer "fraud_count", default: 0
    t.integer "known_domain_id"
    t.integer "legit_count", default: 0
    t.datetime "updated_at", null: false
    t.index ["email_address"], name: "index_known_senders_on_email_address", unique: true
    t.index ["known_domain_id"], name: "index_known_senders_on_known_domain_id"
  end

  create_table "llm_verdicts", force: :cascade do |t|
    t.integer "completion_tokens"
    t.float "confidence"
    t.json "content_patterns", default: {}
    t.datetime "created_at", null: false
    t.integer "email_id", null: false
    t.json "key_findings", default: []
    t.string "model_id"
    t.integer "prompt_tokens"
    t.string "provider", null: false
    t.text "reasoning"
    t.float "response_time_seconds"
    t.integer "score"
    t.datetime "updated_at", null: false
    t.string "verdict"
    t.index ["email_id", "provider"], name: "index_llm_verdicts_on_email_id_and_provider", unique: true
    t.index ["email_id"], name: "index_llm_verdicts_on_email_id"
  end

  create_table "url_scan_results", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.integer "detection_count", default: 0
    t.string "domain"
    t.datetime "expires_at"
    t.boolean "malicious", default: false
    t.json "scan_details", default: {}
    t.string "source", null: false
    t.datetime "updated_at", null: false
    t.string "url", null: false
    t.index ["domain"], name: "index_url_scan_results_on_domain"
    t.index ["expires_at"], name: "index_url_scan_results_on_expires_at"
    t.index ["url", "source"], name: "index_url_scan_results_on_url_and_source", unique: true
  end

  add_foreign_key "active_storage_attachments", "active_storage_blobs", column: "blob_id"
  add_foreign_key "active_storage_variant_records", "active_storage_blobs", column: "blob_id"
  add_foreign_key "analysis_layers", "emails"
  add_foreign_key "analysis_reports", "emails"
  add_foreign_key "community_reports", "emails"
  add_foreign_key "known_senders", "known_domains"
  add_foreign_key "llm_verdicts", "emails"
end
