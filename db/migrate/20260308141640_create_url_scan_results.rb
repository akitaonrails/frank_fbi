class CreateUrlScanResults < ActiveRecord::Migration[8.1]
  def change
    create_table :url_scan_results do |t|
      t.string :url, null: false
      t.string :domain
      t.string :source, null: false
      t.boolean :malicious, default: false
      t.integer :detection_count, default: 0
      t.json :scan_details, default: {}
      t.datetime :expires_at

      t.timestamps
    end

    add_index :url_scan_results, [:url, :source], unique: true
    add_index :url_scan_results, :domain
    add_index :url_scan_results, :expires_at
  end
end
