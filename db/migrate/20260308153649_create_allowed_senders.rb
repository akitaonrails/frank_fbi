class CreateAllowedSenders < ActiveRecord::Migration[8.1]
  def change
    create_table :allowed_senders do |t|
      t.string :email_address, null: false
      t.string :added_by
      t.boolean :active, default: true

      t.timestamps
    end

    add_index :allowed_senders, :email_address, unique: true
  end
end
